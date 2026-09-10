package jsaudit

import (
	"context"

	"github.com/einmsrf/scanner/pkg/httpx"
)

// RunOptions 是一次 JS 审计的完整配置。
type RunOptions struct {
	Collect Options
	Extract ExtractOptions
}

// DefaultRunOptions 返回默认配置。
func DefaultRunOptions() RunOptions {
	return RunOptions{
		Collect: Options{},
		Extract: ExtractOptions{},
	}
}

// Report 是一次 JS 审计的汇总结果。
type Report struct {
	Assets    []Asset
	Findings  []Finding
	Endpoints []Endpoint
	Pages     []string
	Stats     Stats
	Requests  int
	Notes     []string
	Truncated bool
}

// Run 收集并审计目标页面上发现的 JS。
// seeds 是调用方已请求过的页面（首页 / 落地页 / base-path 页面），不会重复请求。
func Run(ctx context.Context, c *httpx.Client, origin string, seeds []*httpx.Response, opts RunOptions) *Report {
	col := Collect(ctx, c, origin, seeds, opts.Collect)
	res := Extract(col.Assets, opts.Extract)
	return &Report{
		Assets:    col.Assets,
		Findings:  res.Findings,
		Endpoints: res.Endpoints,
		Pages:     col.PageURLs,
		Stats:     res.Stats,
		Requests:  col.Requests,
		Notes:     col.Notes,
		Truncated: col.Truncated,
	}
}

// Snippet 是送给语义层打分的一段可疑文本。
type Snippet struct {
	ID   string // 对应 Finding 的稳定标识（类别|文件|值）
	Text string // 带前后上下文的片段
}

// Snippets 返回供语义层打分的可疑片段（DESIGN.md 第 8 节：只发送正则初筛后的
// 可疑片段，带前后 50 字符上下文）。
//
// 只包含“可能误报”的类别：接口路径与注释信息由语义层判危险度；
// 私钥、云 AK 形态等确定性极高的结果不必外发，减少数据外泄面。
func (r *Report) Snippets() []Snippet {
	out := make([]Snippet, 0, len(r.Findings))
	for _, f := range r.Findings {
		switch f.Category {
		case CatPrivateKey, CatCloudKey:
			continue // 形态唯一，无需语义复核，也避免外发真实密钥
		}
		text := f.Context
		if text == "" {
			text = f.Match
		}
		if text == "" {
			continue
		}
		out = append(out, Snippet{ID: snippetID(f), Text: text})
	}
	return out
}

// snippetID 生成 Finding 与语义层结果之间的稳定对应关系。
func snippetID(f Finding) string {
	return string(f.Category) + "|" + f.File + "|" + f.Value
}

// CountBySeverity 统计各严重级别数量。
func (r *Report) CountBySeverity() map[Severity]int {
	m := map[Severity]int{}
	for _, f := range r.Findings {
		m[f.Severity]++
	}
	return m
}

// HighestSeverity 返回最高严重级别，无结果时返回空串。
func (r *Report) HighestSeverity() Severity {
	best := Severity("")
	rank := map[Severity]int{SevHigh: 0, SevMedium: 1, SevLow: 2, SevInfo: 3}
	for _, f := range r.Findings {
		if best == "" || rank[f.Severity] < rank[best] {
			best = f.Severity
		}
	}
	return best
}
