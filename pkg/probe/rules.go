// Package probe 实现漏洞点探测：按指纹族选择探测路径，用内容匹配器判定命中。
//
// 严格遵循 DESIGN.md 第 6 节：只做 GET 判活，绝不发送任何 payload；
// 每条路径必须带内容匹配器，裸 200 不算命中；用 404 基线过滤通配响应。
package probe

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/einmsrf/scanner/pkg/fingerprint"
)

// AlwaysFamily 是“不依赖指纹、对所有目标都跑”的特殊探测族键名。
// 只应放价值高且请求极少的路径，否则会吃掉单目标请求预算。
const AlwaysFamily = "__always__"

// MaxRecordedErrors 限制解析错误上报条数。
const MaxRecordedErrors = 20

// MaxGenericEntries 是通用暴露面字典的条数上限（DESIGN.md 第 6 节）。
// 每条通用项都会对**每个目标**发一次请求，因此必须有硬上限以保住请求预算：
// 指纹层约 15 次 + 通用字典 30 条 + 探测包 ≤24 条 ≈ 69，仍在单目标 100 的预算内。
// 2026-09-10 实战后由 20 放宽到 30，用于纳入 API 文档端点（Swagger/api-docs）。
const MaxGenericEntries = 30

// Spec 是一条探测项。
type Spec struct {
	Path     string `yaml:"path"`
	Matcher  string `yaml:"matcher"`
	Name     string `yaml:"name,omitempty"`
	Severity string `yaml:"severity,omitempty"`
	// Regex 为真时 Matcher 按 Go 正则解释，否则按子串（大小写不敏感）匹配。
	Regex bool `yaml:"regex,omitempty"`
	// Part 为 header 时匹配响应头，默认匹配响应体。
	Part string `yaml:"part,omitempty"`

	re     *regexp.Regexp
	family string
}

// Family 返回该探测项所属的指纹族。
func (s Spec) Family() string { return s.family }

// SeverityOrInfo 返回严重级别，未标注时按 info 处理。
func (s Spec) SeverityOrInfo() string {
	if strings.TrimSpace(s.Severity) == "" {
		return "info"
	}
	return strings.ToLower(strings.TrimSpace(s.Severity))
}

// Title 返回用于展示的名称，缺失时回退到路径。
func (s Spec) Title() string {
	if strings.TrimSpace(s.Name) != "" {
		return strings.TrimSpace(s.Name)
	}
	return s.Path
}

// Library 是探测规则集合。
type Library struct {
	packs    map[string][]Spec // 指纹族 → 探测项
	families []string          // 已排序的族名（不含 AlwaysFamily）
	Always   []Spec            // 不依赖指纹的探测项
	Generic  []Spec            // 通用暴露面字典
}

// PackCount 返回指纹族数量。
func (l *Library) PackCount() int { return len(l.families) }

// SpecCount 返回探测项总数。
func (l *Library) SpecCount() int {
	n := len(l.Always) + len(l.Generic)
	for _, f := range l.families {
		n += len(l.packs[f])
	}
	return n
}

// Families 返回全部指纹族名（已排序）。
func (l *Library) Families() []string {
	out := make([]string, len(l.families))
	copy(out, l.families)
	return out
}

// Pack 返回指定族的探测项。
func (l *Library) Pack(family string) []Spec { return l.packs[family] }

// ParseProbePacks 解析 probe-packs.yaml（族名 → 探测项列表）。
func ParseProbePacks(data []byte) (*Library, error) {
	raw := map[string][]Spec{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("probe: 解析 probe-packs.yaml 失败: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("probe: probe-packs.yaml 为空")
	}

	lib := &Library{packs: map[string][]Spec{}}
	var errs []string
	for family, specs := range raw {
		family = strings.TrimSpace(family)
		if family == "" {
			errs = append(errs, "存在空的族名")
			continue
		}
		valid := make([]Spec, 0, len(specs))
		for i, s := range specs {
			s.family = family
			if err := s.validate(); err != nil {
				errs = append(errs, fmt.Sprintf("%s[%d]: %v", family, i, err))
				continue
			}
			valid = append(valid, s)
		}
		if len(valid) == 0 {
			continue
		}
		if family == AlwaysFamily {
			lib.Always = valid
			continue
		}
		lib.packs[family] = valid
	}
	sort.Strings(lib.families)
	lib.families = make([]string, 0, len(lib.packs))
	for f := range lib.packs {
		lib.families = append(lib.families, f)
	}
	sort.Strings(lib.families)

	if len(errs) > 0 {
		if len(errs) > MaxRecordedErrors {
			errs = errs[:MaxRecordedErrors]
		}
		return lib, fmt.Errorf("probe: probe-packs.yaml 有 %d 条无效探测项: %s", len(errs), strings.Join(errs, "; "))
	}
	return lib, nil
}

// ParseExposure 解析通用暴露面字典（探测项列表）。
func ParseExposure(data []byte) ([]Spec, error) {
	var specs []Spec
	if err := yaml.Unmarshal(data, &specs); err != nil {
		return nil, fmt.Errorf("probe: 解析 exposure.yaml 失败: %w", err)
	}
	var errs []string
	valid := make([]Spec, 0, len(specs))
	for i, s := range specs {
		s.family = "generic"
		if err := s.validate(); err != nil {
			errs = append(errs, fmt.Sprintf("exposure[%d]: %v", i, err))
			continue
		}
		valid = append(valid, s)
	}
	if len(errs) > 0 {
		if len(errs) > MaxRecordedErrors {
			errs = errs[:MaxRecordedErrors]
		}
		return valid, fmt.Errorf("probe: exposure.yaml 有 %d 条无效探测项: %s", len(errs), strings.Join(errs, "; "))
	}
	if len(valid) > MaxGenericEntries {
		return valid, fmt.Errorf("probe: 通用暴露面字典 %d 条，超过设计上限 %d 条（每条都会对每个目标发一次请求）",
			len(valid), MaxGenericEntries)
	}
	return valid, nil
}

// validate 强制“每条路径必须带内容匹配器”（DESIGN.md 第 6 节）。
func (s *Spec) validate() error {
	if strings.TrimSpace(s.Path) == "" {
		return errors.New("缺少 path")
	}
	if !strings.HasPrefix(s.Path, "/") {
		s.Path = "/" + s.Path
	}
	if strings.TrimSpace(s.Matcher) == "" {
		return fmt.Errorf("%s 缺少 matcher（必须带内容匹配器，裸 200 不算命中）", s.Path)
	}
	switch strings.ToLower(strings.TrimSpace(s.Part)) {
	case "", "body":
		s.Part = "body"
	case "header":
		s.Part = "header"
	default:
		return fmt.Errorf("%s 的 part %q 无效（仅 body/header）", s.Path, s.Part)
	}
	if s.Regex {
		re, err := regexp.Compile(s.Matcher)
		if err != nil {
			return fmt.Errorf("%s 的 matcher 正则无效: %w", s.Path, err)
		}
		s.re = re
	}
	return nil
}

// Load 从嵌入的规则文件构建探测库。
func Load(probePacksYAML, exposureYAML []byte) (*Library, error) {
	lib, err := ParseProbePacks(probePacksYAML)
	if err != nil {
		return nil, err
	}
	gen, err := ParseExposure(exposureYAML)
	if err != nil {
		if lib == nil {
			return nil, err
		}
		// 通用字典个别条目无效不应让整个扫描无法进行，但必须让调用方知道。
		lib.Generic = gen
		return lib, err
	}
	lib.Generic = gen
	return lib, nil
}

// SelectFamilies 返回命中指纹所对应的探测族（按族名字典序，保证结果稳定）。
//
// 匹配方式：把族名与指纹的 id/name/product/tags 都规范化（小写、去掉 -/_/. 与空格），
// 族名是这些串的子串（或相等）即视为命中。族名短于 3 个字符不参与匹配，避免噪声。
func (l *Library) SelectFamilies(matches []fingerprint.Match) []string {
	if len(matches) == 0 {
		return nil
	}
	identities := make([]string, 0, len(matches)*4)
	for _, m := range matches {
		r := m.Rule
		if r == nil {
			continue
		}
		identities = append(identities, r.ID, r.Name, r.Product, r.Vendor)
		identities = append(identities, r.Tags...)
	}
	norm := make([]string, 0, len(identities))
	for _, s := range identities {
		if n := normalizeFamily(s); n != "" {
			norm = append(norm, n)
		}
	}
	var out []string
	for _, fam := range l.families {
		nf := normalizeFamily(fam)
		if len(nf) < 3 {
			continue
		}
		for _, id := range norm {
			if id == nf || strings.Contains(id, nf) {
				out = append(out, fam)
				break
			}
		}
	}
	return out
}

// SelectFamiliesFromProducts 是 SelectFamilies 的便捷版本，
// 供只拿到产品名字符串的场景使用（例如语义层聚合结果）。
func (l *Library) SelectFamiliesFromProducts(products []string) []string {
	identities := make([]string, 0, len(products))
	for _, s := range products {
		if n := normalizeFamily(s); n != "" {
			identities = append(identities, n)
		}
	}
	var out []string
	for _, fam := range l.families {
		nf := normalizeFamily(fam)
		if len(nf) < 3 {
			continue
		}
		for _, id := range identities {
			if id == nf || strings.Contains(id, nf) {
				out = append(out, fam)
				break
			}
		}
	}
	return out
}

// normalizeFamily 规范化族名/指纹标识，便于宽松比较。
func normalizeFamily(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '-', '_', '.', ' ', '/', '\\':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
