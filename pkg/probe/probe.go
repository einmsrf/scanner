package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/einmsrf/scanner/pkg/fingerprint"
	"github.com/einmsrf/scanner/pkg/httpx"
)

// 默认上限。探测只在指纹命中对应族时才有开销，这里的上限是硬保护。
const (
	DefaultMaxRequests     = 40 // 单目标探测请求上限（指纹层另有开销，总预算 100）
	DefaultMaxFamilyProbes = 24 // 指纹族探测项上限，避免家族过多时吃满预算
	DefaultMaxBasesPerSpec = 2  // 单个探测项最多尝试的 base 数
	evidenceMaxLen         = 120
)

// Options 控制单次探测开销。零值即默认值。
type Options struct {
	MaxRequests     int
	MaxFamilyProbes int
	MaxBasesPerSpec int
	SkipGeneric     bool     // 跳过通用暴露面字典
	SkipAlways      bool     // 跳过 __always__ 族
	Bases           []string // 候选 base（如 /oa），默认仅根 ""；顺序即尝试顺序
}

func (o Options) withDefaults() Options {
	if o.MaxRequests <= 0 {
		o.MaxRequests = DefaultMaxRequests
	}
	if o.MaxFamilyProbes <= 0 {
		o.MaxFamilyProbes = DefaultMaxFamilyProbes
	}
	if o.MaxBasesPerSpec <= 0 {
		o.MaxBasesPerSpec = DefaultMaxBasesPerSpec
	}
	if len(o.Bases) == 0 {
		o.Bases = []string{""}
	}
	return o
}

// Finding 是一条命中的暴露面。
type Finding struct {
	Family   string // 触发的指纹族（generic 表示通用字典）
	Spec     Spec
	URL      string
	Status   int
	Evidence string
}

// Report 是一次探测的结果。
type Report struct {
	Findings  []Finding
	Families  []string // 本次实际启用的指纹族
	Probed    []string // 实际请求过的 URL
	Requests  int
	Truncated bool
	Notes     []string
}

// Prober 执行探测，可安全复用。
type Prober struct {
	lib *Library
}

// New 构建探测器。
func New(lib *Library) *Prober { return &Prober{lib: lib} }

// Library 返回探测规则库。
func (p *Prober) Library() *Library { return p.lib }

// Run 对单个站点执行探测。baseline 可为 nil（此时不做通配过滤，误报率会升高）。
func (p *Prober) Run(
	ctx context.Context,
	c *httpx.Client,
	origin string,
	matches []fingerprint.Match,
	baseline *httpx.Baseline,
	opts Options,
) *Report {
	opts = opts.withDefaults()
	rep := &Report{}
	if origin == "" {
		rep.Notes = append(rep.Notes, "origin 为空，跳过探测")
		return rep
	}
	origin = strings.TrimSuffix(origin, "/")

	// 1. 选择要跑的探测项：__always__ → 通用字典 → 命中指纹族。
	families := p.lib.SelectFamilies(matches)
	rep.Families = families

	var queue []Spec
	if !opts.SkipAlways {
		queue = append(queue, p.lib.Always...)
	}
	if !opts.SkipGeneric {
		queue = append(queue, p.lib.Generic...)
	}
	familyUsed := 0
	for _, fam := range families {
		if familyUsed >= opts.MaxFamilyProbes {
			rep.Truncated = true
			rep.Notes = append(rep.Notes, fmt.Sprintf("指纹族探测项达到上限 %d，部分族未探测", opts.MaxFamilyProbes))
			break
		}
		for _, s := range p.lib.Pack(fam) {
			if familyUsed >= opts.MaxFamilyProbes {
				rep.Truncated = true
				rep.Notes = append(rep.Notes, fmt.Sprintf("指纹族探测项达到上限 %d，部分族未探测", opts.MaxFamilyProbes))
				break
			}
			queue = append(queue, s)
			familyUsed++
		}
	}

	// 2. 逐个探测。
	// 软 404 站点（通配 200）下换 base 也无法区分，故只试第一个 base 省预算。
	bases := opts.Bases
	if baseline != nil && baseline.Wildcard && len(bases) > opts.MaxBasesPerSpec {
		notes := bases[opts.MaxBasesPerSpec:]
		bases = bases[:opts.MaxBasesPerSpec]
		rep.Notes = append(rep.Notes, fmt.Sprintf("站点为通配 200（软 404），仅探测前 %d 个 base，忽略 %v", len(bases), notes))
	}

	seen := map[string]bool{} // 同一 (path, family) 只报一次
	for _, spec := range queue {
		if rep.Requests >= opts.MaxRequests {
			rep.Truncated = true
			rep.Notes = append(rep.Notes, fmt.Sprintf("探测请求达到上限 %d，剩余 %d 条未探测", opts.MaxRequests, len(queue)))
			break
		}
		if c.Remaining() <= 0 {
			rep.Truncated = true
			rep.Notes = append(rep.Notes, "目标请求总预算已用尽，探测提前结束")
			break
		}
		key := spec.family + " " + spec.Path
		if seen[key] {
			continue
		}
		seen[key] = true

		triedBases := 0
		for _, base := range bases {
			if triedBases >= opts.MaxBasesPerSpec {
				break
			}
			triedBases++
			u := origin + joinBase(base, spec.Path)
			resp, err := c.Get(ctx, u)
			rep.Requests++
			if err != nil {
				continue
			}
			rep.Probed = append(rep.Probed, resp.URL)

			// 用 404 基线过滤通配/软 404 响应（DESIGN.md 第 6 节）。
			if baseline != nil && baseline.SameAs(resp) {
				continue
			}
			if resp.Status >= 400 {
				continue
			}
			hit, ev := spec.evaluate(resp)
			if hit {
				rep.Findings = append(rep.Findings, Finding{
					Family:   spec.family,
					Spec:     spec,
					URL:      resp.URL,
					Status:   resp.Status,
					Evidence: ev,
				})
				break
			}
			// 该 base 下路径存在但不是目标内容，不再换 base 浪费预算。
			break
		}
	}

	sort.SliceStable(rep.Findings, func(i, j int) bool {
		if rep.Findings[i].Family != rep.Findings[j].Family {
			return rep.Findings[i].Family < rep.Findings[j].Family
		}
		return rep.Findings[i].Spec.Path < rep.Findings[j].Spec.Path
	})
	return rep
}

// evaluate 用内容匹配器判定命中。裸 200 不算命中。
func (s *Spec) evaluate(resp *httpx.Response) (bool, string) {
	if resp == nil {
		return false, ""
	}
	var text string
	if s.Part == "header" {
		text = headerText(resp)
	} else {
		text = resp.Text()
	}
	if text == "" {
		return false, ""
	}

	if s.re != nil {
		loc := s.re.FindStringIndex(text)
		if loc == nil {
			return false, ""
		}
		return true, "regex:" + clip(text[loc[0]:loc[1]])
	}
	// 子串匹配，大小写不敏感（降低因大小写差异漏报）。
	idx := strings.Index(strings.ToLower(text), strings.ToLower(s.Matcher))
	if idx < 0 {
		return false, ""
	}
	end := idx + len(s.Matcher)
	if end > len(text) {
		end = len(text)
	}
	return true, "matcher:" + clip(text[idx:end])
}

// joinBase 把 base 与探测路径拼起来。base 为 "" 或 "/" 时即根路径。
func joinBase(base, p string) string {
	base = strings.TrimSpace(base)
	if base == "" || base == "/" {
		return p
	}
	if !strings.HasPrefix(base, "/") {
		base = "/" + base
	}
	return strings.TrimSuffix(base, "/") + p
}

// headerText 序列化响应头，键排序保证结果稳定。
func headerText(resp *httpx.Response) string {
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		for _, v := range resp.Header[k] {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// clip 截断证据串并压成单行。始终返回合法 UTF-8（目标站点可能有非 UTF-8 字节）。
func clip(s string) string {
	r := []rune(strings.Join(strings.Fields(s), " "))
	if len(r) > evidenceMaxLen {
		return string(r[:evidenceMaxLen]) + "…"
	}
	return string(r)
}

// BodyHash 返回响应体的 sha256（供报告层做证据去重）。
func BodyHash(resp *httpx.Response) string {
	if resp == nil {
		return ""
	}
	sum := sha256.Sum256(resp.Body)
	return hex.EncodeToString(sum[:])
}
