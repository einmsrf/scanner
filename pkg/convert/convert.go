// Package convert 把 FingerprintHub 的 nuclei YAML 模板离线转换成
// scanner 内部的紧凑 JSON 指纹库（fingerprint.Library）。
//
// 只保留能静态化的子集：path + word/regex/favicon matcher。
// 含 DSL、模板变量、extractor、status/size 等复杂规则的模板直接丢弃，
// 并计入 Stats 供 scanner update 汇报。见 DESIGN.md 第 5.1 节。
package convert

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/einmsrf/scanner/pkg/fingerprint"
)

// DefaultTemplateDir 是 FingerprintHub 仓库中 Web 指纹模板所在目录。
const DefaultTemplateDir = "web-fingerprint"

// MaxRecordedErrors 限制记录的错误条数，避免输出爆炸。
const MaxRecordedErrors = 25

// Stats 是转换过程的统计。
type Stats struct {
	Files           int      // 扫到的 yaml 文件数
	Rules           int      // 成功转换的规则数
	SkippedFiles    int      // 无可用内容而跳过的文件数
	DroppedMatchers int      // 因类型不支持被丢弃的 matcher 数
	DroppedRules    int      // 因缺少 path/matcher 被丢弃的规则数
	Errors          []string // 解析失败的文件（最多 MaxRecordedErrors 条）
}

// String 便于 CLI 打印。
func (s *Stats) String() string {
	return fmt.Sprintf("文件 %d（跳过 %d）、规则 %d、丢弃 matcher %d、丢弃规则 %d、解析失败 %d",
		s.Files, s.SkippedFiles, s.Rules, s.DroppedMatchers, s.DroppedRules, len(s.Errors))
}

// ConvertDir 转换磁盘目录下的所有 *.yaml。
func ConvertDir(root, source string) (*fingerprint.Library, *Stats, error) {
	return ConvertFS(os.DirFS(root), source)
}

// ConvertFS 转换任意 fs.FS（磁盘目录或 zip.Reader）下的所有 *.yaml。
func ConvertFS(fsys fs.FS, source string) (*fingerprint.Library, *Stats, error) {
	st := &Stats{}
	var out []fingerprint.Rule
	used := make(map[string]bool)

	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			st.recordErr(p, err)
			return nil // 单个文件出错不中断整体转换
		}
		if d.IsDir() {
			return nil
		}
		if !strings.EqualFold(path.Ext(p), ".yaml") {
			return nil
		}
		st.Files++
		data, rerr := fs.ReadFile(fsys, p)
		if rerr != nil {
			st.recordErr(p, rerr)
			return nil
		}
		tpl, perr := ParseTemplate(data)
		if perr != nil {
			st.recordErr(p, perr)
			return nil
		}
		rules, droppedMatchers, droppedRules := tpl.Rules()
		st.DroppedMatchers += droppedMatchers
		st.DroppedRules += droppedRules
		if len(rules) == 0 {
			st.SkippedFiles++
			return nil
		}
		// 上游有 70+ 个 ID 被多个模板复用（同产品的不同入口），
		// 全部保留并加后缀去重，避免丢失探测能力。
		for _, r := range rules {
			r.ID = uniqueID(r.ID, used)
			used[r.ID] = true
			out = append(out, r)
		}
		return nil
	})
	if err != nil {
		return nil, st, err
	}

	// 按 ID 排序，保证每次转换产物稳定可比对。
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })

	lib := &fingerprint.Library{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Source:      source,
		Count:       len(out),
		Rules:       out,
	}
	st.Rules = lib.Count
	return lib, st, nil
}

// uniqueID 在 ID 已被占用时追加 #N 后缀，直到唯一。
func uniqueID(id string, used map[string]bool) string {
	if !used[id] {
		return id
	}
	for n := 2; ; n++ {
		cand := fmt.Sprintf("%s#%d", id, n)
		if !used[cand] {
			return cand
		}
	}
}

func (s *Stats) recordErr(where string, err error) {
	if len(s.Errors) >= MaxRecordedErrors {
		return
	}
	s.Errors = append(s.Errors, fmt.Sprintf("%s: %v", where, err))
}

// MarshalLibrary 输出紧凑 JSON（带结尾换行，便于 git diff）。
func MarshalLibrary(lib *fingerprint.Library) ([]byte, error) {
	b, err := json.Marshal(lib)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ---------- 模板解析 ----------

// Template 是 nuclei YAML 模板中我们关心的字段子集。
// 未列出的字段（author/severity/extractors/headers 等）由 yaml 解码器自动忽略。
type Template struct {
	ID   string `yaml:"id"`
	Info struct {
		Name     string `yaml:"name"`
		Tags     string `yaml:"tags"`
		Metadata struct {
			Product string `yaml:"product"`
			Vendor  string `yaml:"vendor"`
		} `yaml:"metadata"`
	} `yaml:"info"`
	HTTP []HTTPBlock `yaml:"http"`
}

// HTTPBlock 是一个 http 请求块。
type HTTPBlock struct {
	Method            string            `yaml:"method"`
	Path              []string          `yaml:"path"`
	MatchersCondition string            `yaml:"matchers-condition"`
	Matchers          []RawMatcher      `yaml:"matchers"`
	Headers           map[string]string `yaml:"headers"`
	Extractors        []any             `yaml:"extractors"`
}

// RawMatcher 对应模板里的一条 matcher 原始写法。
type RawMatcher struct {
	Type            string   `yaml:"type"`
	Words           []string `yaml:"words"`
	Regex           []string `yaml:"regex"`
	Hash            []string `yaml:"hash"`
	Part            string   `yaml:"part"`
	CaseInsensitive bool     `yaml:"case-insensitive"`
	Condition       string   `yaml:"condition"`
	Name            string   `yaml:"name"`

	// 以下字段一旦出现即视为复杂规则，该 matcher 被丢弃。
	DSL      []string `yaml:"dsl"`
	Status   []int    `yaml:"status"`
	Size     []int    `yaml:"size"`
	Binary   []string `yaml:"binary"`
	XPath    []string `yaml:"xpath"`
	Encoding string   `yaml:"encoding"`
	Negative bool     `yaml:"negative"`
}

// ParseTemplate 解析单个模板文件。
func ParseTemplate(data []byte) (*Template, error) {
	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// Rules 把模板展开成规则列表，同时返回丢弃计数。
// 一个模板可能含多个 http 块，每个块对应一条规则（ID 加后缀保证唯一）。
func (t *Template) Rules() (rules []fingerprint.Rule, droppedMatchers, droppedRules int) {
	if len(t.HTTP) == 0 {
		return nil, 0, 0
	}
	baseID := strings.TrimSpace(t.ID)
	if baseID == "" {
		baseID = strings.TrimSpace(t.Info.Name)
	}
	if baseID == "" {
		return nil, 0, len(t.HTTP)
	}

	tags := splitTags(t.Info.Tags)

	for i, blk := range t.HTTP {
		paths := normalizePaths(blk.Path)
		if len(paths) == 0 {
			droppedRules++
			continue
		}
		var ms []fingerprint.Matcher
		for _, rm := range blk.Matchers {
			m, ok := convertMatcher(rm)
			if !ok {
				droppedMatchers++
				continue
			}
			ms = append(ms, m)
		}
		if len(ms) == 0 {
			droppedRules++
			continue
		}
		id := baseID
		if len(t.HTTP) > 1 {
			id = fmt.Sprintf("%s#%d", baseID, i+1)
		}
		rules = append(rules, fingerprint.Rule{
			ID:       id,
			Name:     firstNonEmpty(strings.TrimSpace(t.Info.Name), baseID),
			Product:  strings.TrimSpace(t.Info.Metadata.Product),
			Vendor:   strings.TrimSpace(t.Info.Metadata.Vendor),
			Tags:     tags,
			Paths:    paths,
			Matchers: ms,
			Cond:     normalizeCond(blk.MatchersCondition),
		})
	}
	return rules, droppedMatchers, droppedRules
}

// convertMatcher 把原始 matcher 转成内部形式；不支持的返回 false。
func convertMatcher(rm RawMatcher) (fingerprint.Matcher, bool) {
	// 含 DSL、status、size 等复杂条件的 matcher 一律丢弃。
	if len(rm.DSL) > 0 || len(rm.Status) > 0 || len(rm.Size) > 0 ||
		len(rm.Binary) > 0 || len(rm.XPath) > 0 || rm.Negative || rm.Encoding != "" {
		return fingerprint.Matcher{}, false
	}
	part := fingerprint.PartBody
	if strings.EqualFold(strings.TrimSpace(rm.Part), fingerprint.PartHeader) {
		part = fingerprint.PartHeader
	}
	switch strings.ToLower(strings.TrimSpace(rm.Type)) {
	case fingerprint.MatcherWord:
		vals := cleanList(rm.Words)
		if len(vals) == 0 {
			return fingerprint.Matcher{}, false
		}
		return fingerprint.Matcher{
			Type:  fingerprint.MatcherWord,
			Part:  part,
			Value: vals,
			CI:    rm.CaseInsensitive,
			Cond:  normalizeCond(rm.Condition),
		}, true
	case fingerprint.MatcherRegex:
		vals := cleanList(rm.Regex)
		if len(vals) == 0 {
			return fingerprint.Matcher{}, false
		}
		return fingerprint.Matcher{
			Type:  fingerprint.MatcherRegex,
			Part:  part,
			Value: vals,
			CI:    rm.CaseInsensitive,
			Cond:  normalizeCond(rm.Condition),
		}, true
	case fingerprint.MatcherFavicon:
		vals := cleanList(rm.Hash)
		if len(vals) == 0 {
			return fingerprint.Matcher{}, false
		}
		return fingerprint.Matcher{Type: fingerprint.MatcherFavicon, Value: vals}, true
	default:
		// text / application / dsl / status / size / word(空) 等
		return fingerprint.Matcher{}, false
	}
}

// normalizePaths 把 '{{BaseURL}}/foo' 之类的写法统一成相对路径 '/foo'。
// 含无法静态化变量（{{RootURL}} 等）的路径丢弃。
func normalizePaths(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range in {
		p, ok := relPath(raw)
		if !ok || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func relPath(raw string) (string, bool) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", false
	}
	const base = "{{BaseURL}}"
	if strings.HasPrefix(p, base) {
		r := strings.TrimPrefix(p, base)
		if r == "" {
			r = "/"
		}
		if !strings.HasPrefix(r, "/") {
			r = "/" + r
		}
		return stripQuery(r), true
	}
	if i := strings.Index(p, "://"); i >= 0 {
		rest := p[i+3:]
		j := strings.IndexByte(rest, '/')
		if j < 0 {
			return "/", true
		}
		return stripQuery(rest[j:]), true
	}
	// 其它模板变量无法静态展开
	if strings.Contains(p, "{{") || strings.Contains(p, "}}") {
		return "", false
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return stripQuery(p), true
}

func stripQuery(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if p == "" {
		return "/"
	}
	return p
}

func cleanList(in []string) []string {
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func splitTags(s string) []string {
	var out []string
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		// detect/tech 是模板固定标签，无区分度，去掉以减少体积。
		if t == "" || t == "detect" || t == "tech" {
			continue
		}
		out = append(out, t)
	}
	return out
}

func normalizeCond(s string) string {
	if strings.EqualFold(strings.TrimSpace(s), fingerprint.CondAnd) {
		return fingerprint.CondAnd
	}
	return fingerprint.CondOr
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
