// Package report 汇总扫描结果并输出三种形态：终端彩色、JSON（机器可读）、
// HTML（人工研判）。见 DESIGN.md 第 10 节。
package report

import (
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Severity 是统一的严重级别。probe 与 jsaudit 的级别字符串都归一到此。
type Severity string

// 级别取值。
const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// SeverityRank 返回排序权重（越小越严重）。未知级别按 info 处理。
func SeverityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(SevCritical):
		return 0
	case string(SevHigh):
		return 1
	case string(SevMedium):
		return 2
	case string(SevLow):
		return 3
	default:
		return 4
	}
}

// SeverityDisplay 返回中文级别名。
func SeverityDisplay(s string) string {
	switch SeverityRank(s) {
	case 0:
		return "严重"
	case 1:
		return "高危"
	case 2:
		return "中危"
	case 3:
		return "低危"
	default:
		return "信息"
	}
}

// FingerprintHit 是一条命中的指纹。
type FingerprintHit struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Product  string `json:"product,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Path     string `json:"path"`
	URL      string `json:"url"`
	Via      string `json:"via,omitempty"` // landing | path | subdir | favicon
	Evidence string `json:"evidence,omitempty"`
}

// Display 返回适合展示的产品名。
func (f FingerprintHit) Display() string {
	for _, s := range []string{f.Product, f.Name, f.ID} {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return f.ID
}

// Exposure 是一条判活命中的暴露面。
type Exposure struct {
	Family   string `json:"family"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Path     string `json:"path"`
	URL      string `json:"url,omitempty"`
	Status   int    `json:"status,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

// SemanticNote 是语义层对一条 JS 发现的判定（未启用时为 Judged=false）。
type SemanticNote struct {
	Judged      bool    `json:"judged"`
	IsSensitive bool    `json:"is_sensitive"`
	Reason      string  `json:"reason,omitempty"`
	Confidence  float64 `json:"confidence,omitempty"`
}

// JSFinding 是一条 JS 敏感信息发现（含语义层结论）。
type JSFinding struct {
	Category    string  `json:"category"`               // 中文类别名
	CategoryKey string  `json:"category_key,omitempty"` // 类别标识，用于与语义层结果对齐
	Severity    string  `json:"severity"`
	RuleID      string  `json:"rule_id,omitempty"`
	File        string  `json:"file"`
	Source      string  `json:"source,omitempty"` // external | inline | sourcemap
	Line        int     `json:"line,omitempty"`
	Value       string  `json:"value,omitempty"`
	Decoded     string  `json:"decoded,omitempty"`
	Evidence    string  `json:"evidence,omitempty"`
	Context     string  `json:"context,omitempty"`
	Entropy     float64 `json:"entropy,omitempty"`
	Note        string  `json:"note,omitempty"`

	Semantic *SemanticNote `json:"semantic,omitempty"`
}

// JSEndpoint 是从 JS 提取到的接口路径（只展示，绝不请求）。
// Semantic 是语义层对"该接口是否像高危/高权限接口"的判定。
type JSEndpoint struct {
	Path     string        `json:"path"`
	Count    int           `json:"count,omitempty"`
	Semantic *SemanticNote `json:"semantic,omitempty"`
}

// EndpointID 返回接口路径对应的语义层条目标识（构建与查询两侧共用，
// 保证判定结果能对齐回具体接口）。
func EndpointID(path string) string { return "endpoint|" + path }

// JSSection 是单个目标的 JS 审计汇总。
type JSSection struct {
	AssetsScanned int          `json:"assets_scanned"`
	Pages         []string     `json:"pages,omitempty"`
	SourceMapHits int          `json:"sourcemap_hits,omitempty"`
	Findings      []JSFinding  `json:"findings,omitempty"`
	Endpoints     []JSEndpoint `json:"endpoints,omitempty"`
	Notes         []string     `json:"notes,omitempty"`
}

// TargetReport 是单个目标的扫描结果。
type TargetReport struct {
	// Target 是用户输入的原始形式；URL 是实际扫描的最终 URL。
	Target   string `json:"target"`
	URL      string `json:"url,omitempty"`
	Scheme   string `json:"scheme,omitempty"`
	Status   int    `json:"status,omitempty"`
	Title    string `json:"title,omitempty"`
	Server   string `json:"server,omitempty"`
	Error    string `json:"error,omitempty"`
	Duration string `json:"duration,omitempty"`

	Fingerprints []FingerprintHit `json:"fingerprints,omitempty"`
	Exposures    []Exposure       `json:"exposures,omitempty"`
	JS           *JSSection       `json:"js,omitempty"`

	Requests int      `json:"requests,omitempty"`
	Notes    []string `json:"notes,omitempty"`
}

// OK 表示该目标是否扫描成功（没有致命错误）。
func (t *TargetReport) OK() bool { return t.Error == "" }

// HighestSeverity 返回该目标最严重的级别（普通 string，便于模板函数直接使用），
// 无发现时返回空串。
func (t *TargetReport) HighestSeverity() string {
	best := 5
	out := ""
	consider := func(s string) {
		if r := SeverityRank(s); r < best {
			best = r
			out = strings.ToLower(strings.TrimSpace(s))
		}
	}
	for _, e := range t.Exposures {
		consider(e.Severity)
	}
	if t.JS != nil {
		for _, f := range t.JS.Findings {
			consider(f.Severity)
		}
	}
	return out
}

// Summary 是整份报告的统计。
type Summary struct {
	Targets       int    `json:"targets"`
	TargetsOK     int    `json:"targets_ok"`
	TargetsFailed int    `json:"targets_failed"`
	Fingerprints  int    `json:"fingerprints"`
	Exposures     int    `json:"exposures"`
	JSFindings    int    `json:"js_findings"`
	Endpoints     int    `json:"endpoints"`
	Critical      int    `json:"critical"`
	High          int    `json:"high"`
	Medium        int    `json:"medium"`
	Low           int    `json:"low"`
	Info          int    `json:"info"`
	Requests      int    `json:"requests"`
	Duration      string `json:"duration,omitempty"`
}

// Report 是整份扫描报告。
type Report struct {
	Tool         string          `json:"tool"`
	Version      string          `json:"version"`
	GeneratedAt  string          `json:"generated_at"`
	Fingerprints string          `json:"fingerprint_source,omitempty"` // 指纹库来源描述
	Semantic     string          `json:"semantic,omitempty"`           // 语义层状态描述
	Args         string          `json:"args,omitempty"`               // 命令行摘要，便于复现
	Targets      []*TargetReport `json:"targets"`
	Summary      Summary         `json:"summary"`
}

// New 创建带工具信息的空报告。
func New(tool, version string) *Report {
	return &Report{
		Tool:        tool,
		Version:     version,
		GeneratedAt: time.Now().Format(time.RFC3339),
	}
}

// CountSeverity 把某个级别计入汇总。
func (s *Summary) CountSeverity(sev string) {
	switch SeverityRank(sev) {
	case 0:
		s.Critical++
	case 1:
		s.High++
	case 2:
		s.Medium++
	case 3:
		s.Low++
	default:
		s.Info++
	}
}

// Finalize 计算汇总统计、规整字符串并做稳定排序。
// 会在最后调用 Sanitize，保证后续三种输出（终端/JSON/HTML）都是合法 UTF-8。
func (r *Report) Finalize(d time.Duration) {
	s := Summary{Targets: len(r.Targets), Duration: d.Round(time.Millisecond).String()}
	for _, t := range r.Targets {
		if t.OK() {
			s.TargetsOK++
		} else {
			s.TargetsFailed++
		}
		s.Requests += t.Requests
		s.Fingerprints += len(t.Fingerprints)
		s.Exposures += len(t.Exposures)
		for _, e := range t.Exposures {
			s.CountSeverity(e.Severity)
		}
		if t.JS != nil {
			s.JSFindings += len(t.JS.Findings)
			s.Endpoints += len(t.JS.Endpoints)
			for _, f := range t.JS.Findings {
				s.CountSeverity(f.Severity)
			}
		}
		// 目标内按严重度排序，便于阅读
		sort.SliceStable(t.Fingerprints, func(i, j int) bool {
			return t.Fingerprints[i].Display() < t.Fingerprints[j].Display()
		})
		sort.SliceStable(t.Exposures, func(i, j int) bool {
			if SeverityRank(t.Exposures[i].Severity) != SeverityRank(t.Exposures[j].Severity) {
				return SeverityRank(t.Exposures[i].Severity) < SeverityRank(t.Exposures[j].Severity)
			}
			return t.Exposures[i].Path < t.Exposures[j].Path
		})
		if t.JS != nil {
			sort.SliceStable(t.JS.Findings, func(i, j int) bool {
				a, b := t.JS.Findings[i], t.JS.Findings[j]
				if SeverityRank(a.Severity) != SeverityRank(b.Severity) {
					return SeverityRank(a.Severity) < SeverityRank(b.Severity)
				}
				if a.Category != b.Category {
					return a.Category < b.Category
				}
				return a.File < b.File
			})
		}
	}
	r.Summary = s
	r.Sanitize()
}

// validUTF8 把非法 UTF-8 字节替换为 U+FFFD。
// 目标站点常见 GBK 等非 UTF-8 编码，混进报告会让 JSON/HTML 整个文件损坏。
func validUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "�")
}

// Sanitize 就地规整报告里的所有字符串为合法 UTF-8。
// 这是唯一的收口点：三种输出都直接依赖这些字段。
func (r *Report) Sanitize() {
	r.Tool = validUTF8(r.Tool)
	r.Version = validUTF8(r.Version)
	r.GeneratedAt = validUTF8(r.GeneratedAt)
	r.Fingerprints = validUTF8(r.Fingerprints)
	r.Semantic = validUTF8(r.Semantic)
	r.Args = validUTF8(r.Args)
	r.Summary.Duration = validUTF8(r.Summary.Duration)

	for _, t := range r.Targets {
		if t == nil {
			continue
		}
		t.Target = validUTF8(t.Target)
		t.URL = validUTF8(t.URL)
		t.Scheme = validUTF8(t.Scheme)
		t.Title = validUTF8(t.Title)
		t.Server = validUTF8(t.Server)
		t.Error = validUTF8(t.Error)
		t.Duration = validUTF8(t.Duration)
		for i := range t.Notes {
			t.Notes[i] = validUTF8(t.Notes[i])
		}
		for i := range t.Fingerprints {
			f := &t.Fingerprints[i]
			f.ID = validUTF8(f.ID)
			f.Name = validUTF8(f.Name)
			f.Product = validUTF8(f.Product)
			f.Vendor = validUTF8(f.Vendor)
			f.Path = validUTF8(f.Path)
			f.URL = validUTF8(f.URL)
			f.Via = validUTF8(f.Via)
			f.Evidence = validUTF8(f.Evidence)
		}
		for i := range t.Exposures {
			e := &t.Exposures[i]
			e.Family = validUTF8(e.Family)
			e.Name = validUTF8(e.Name)
			e.Severity = validUTF8(e.Severity)
			e.Path = validUTF8(e.Path)
			e.URL = validUTF8(e.URL)
			e.Evidence = validUTF8(e.Evidence)
		}
		if t.JS == nil {
			continue
		}
		js := t.JS
		for i := range js.Pages {
			js.Pages[i] = validUTF8(js.Pages[i])
		}
		for i := range js.Notes {
			js.Notes[i] = validUTF8(js.Notes[i])
		}
		for i := range js.Findings {
			f := &js.Findings[i]
			f.Category = validUTF8(f.Category)
			f.CategoryKey = validUTF8(f.CategoryKey)
			f.Severity = validUTF8(f.Severity)
			f.RuleID = validUTF8(f.RuleID)
			f.File = validUTF8(f.File)
			f.Source = validUTF8(f.Source)
			f.Value = validUTF8(f.Value)
			f.Decoded = validUTF8(f.Decoded)
			f.Evidence = validUTF8(f.Evidence)
			f.Context = validUTF8(f.Context)
			f.Note = validUTF8(f.Note)
			if f.Semantic != nil {
				f.Semantic.Reason = validUTF8(f.Semantic.Reason)
			}
		}
		for i := range js.Endpoints {
			js.Endpoints[i].Path = validUTF8(js.Endpoints[i].Path)
			if e := js.Endpoints[i].Semantic; e != nil {
				e.Reason = validUTF8(e.Reason)
			}
		}
	}
}
