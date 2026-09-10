package report

import (
	"regexp"
	"strings"

	"github.com/einmsrf/scanner/pkg/fingerprint"
	"github.com/einmsrf/scanner/pkg/jsaudit"
	"github.com/einmsrf/scanner/pkg/probe"
)

// FromFingerprintMatches 把指纹引擎的命中转换成报告条目。
func FromFingerprintMatches(matches []fingerprint.Match) []FingerprintHit {
	out := make([]FingerprintHit, 0, len(matches))
	for i := range matches {
		m := &matches[i]
		if m.Rule == nil {
			continue
		}
		out = append(out, FingerprintHit{
			ID:       m.Rule.ID,
			Name:     m.Rule.Name,
			Product:  m.Rule.Product,
			Vendor:   m.Rule.Vendor,
			Path:     m.Path,
			URL:      m.URL,
			Via:      m.Via,
			Evidence: m.Evidence,
		})
	}
	return out
}

// FromProbeFindings 把探测结果转换成报告条目。
func FromProbeFindings(findings []probe.Finding) []Exposure {
	out := make([]Exposure, 0, len(findings))
	for i := range findings {
		f := &findings[i]
		out = append(out, Exposure{
			Family:   f.Family,
			Name:     f.Spec.Title(),
			Severity: f.Spec.SeverityOrInfo(),
			Path:     f.Spec.Path,
			URL:      f.URL,
			Status:   f.Status,
			Evidence: f.Evidence,
		})
	}
	return out
}

// VerdictFunc 返回某条条目（JS 发现或接口路径）的语义层判定，找不到时返回 nil。
type VerdictFunc func(id string) *SemanticNote

// FromJSAudit 把 JS 审计结果转换成报告章节。
// verdicts 可为 nil（语义层未启用），此时所有发现都标记为未判定。
func FromJSAudit(rep *jsaudit.Report, verdicts VerdictFunc) *JSSection {
	if rep == nil {
		return nil
	}
	sec := &JSSection{
		AssetsScanned: len(rep.Assets),
		Pages:         rep.Pages,
		Notes:         rep.Notes,
	}
	for _, a := range rep.Assets {
		if a.Source == "sourcemap" {
			sec.SourceMapHits++
		}
	}
	for _, f := range rep.Findings {
		jf := JSFinding{
			Category:    f.Category.Display(),
			CategoryKey: string(f.Category),
			Severity:    string(f.Severity),
			RuleID:      f.RuleID,
			File:        f.File,
			Source:      f.Source,
			Line:        f.Line,
			Value:       f.Value,
			Decoded:     f.Decoded,
			Evidence:    f.Match,
			Context:     f.Context,
			Entropy:     round2(f.Entropy),
			Note:        f.Note,
		}
		if verdicts != nil {
			jf.Semantic = verdicts(jsaudit.SnippetID(f))
		}
		sec.Findings = append(sec.Findings, jf)
	}
	for _, e := range rep.Endpoints {
		je := JSEndpoint{Path: e.Path, Count: e.Count}
		if verdicts != nil {
			je.Semantic = verdicts(EndpointID(e.Path))
		}
		sec.Endpoints = append(sec.Endpoints, je)
	}
	return sec
}

// titleRe 从 HTML 里取 <title>。
var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// ExtractTitle 从响应体里提取页面标题（失败返回空串）。
func ExtractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	t := strings.Join(strings.Fields(string(m[1])), " ")
	r := []rune(t)
	if len(r) > 120 {
		return string(r[:120]) + "…"
	}
	return t
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
