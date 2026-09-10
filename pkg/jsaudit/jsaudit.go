package jsaudit

import (
	"context"
	"sort"
	"strings"

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
		out = append(out, Snippet{ID: SnippetID(f), Text: text})
	}
	return out
}

// SnippetID 生成 Finding 与语义层判定结果之间的稳定对应标识。
// 报告层必须用同一函数取标识，否则语义结论无法对齐到发现。
func SnippetID(f Finding) string {
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

// MinPrefixCount 是把某个一级前缀当作"部署 base"候选所需的最少出现次数。
const MinPrefixCount = 3

// prefixStoplist 是不适合作为部署 base 的一级前缀：静态资源目录、
// 通用应用路由名（不是反代前缀）、以及各种噪声。
var prefixStoplist = map[string]bool{
	// 静态资源
	"static": true, "assets": true, "asset": true, "js": true, "css": true,
	"img": true, "images": true, "image": true, "fonts": true, "font": true,
	"media": true, "public": true, "dist": true, "build": true, "chunks": true,
	// 常见应用路由（做了也不会命中部署目录，白白消耗预算）
	"home": true, "index": true, "login": true, "logout": true, "dashboard": true,
	"property": true, "properties": true, "user": true, "users": true, "about": true,
	"help": true, "error": true, "404": true, "404.html": true, "favicon.ico": true,
	"video": true, "audio": true, "docs": true, "doc": true,
}

// BasePrefixCandidates 从提取到的接口路径里聚合一级前缀，返回适合当作
// "部署 base"重试的前缀（如 nginx 反代前缀 /api），按出现次数降序、最多 max 个。
//
// 这是 DESIGN.md 第 5.2 节新增的第 5 层证据来源：实战里应用常挂在反代前缀下
// （案例 yhtipipc.com 的 /api/v2/api-docs），而落地页 HTML 的链接看不到该前缀，
// 原有四层兜底全部落空。
//
// 注意：前缀**全部来自目标自身 JS 里出现的路径**，不是内置猜测字典，
// 因此不违反"不做目录爆破"的约束。
func (r *Report) BasePrefixCandidates(max int) []string {
	if r == nil || max <= 0 {
		return nil
	}
	counts := map[string]int{}
	for _, e := range r.Endpoints {
		p := e.Path
		if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
			continue // 只看站内绝对路径
		}
		seg := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 2)[0]
		if seg == "" || len(seg) < 2 {
			continue
		}
		low := strings.ToLower(seg)
		if prefixStoplist[low] {
			continue
		}
		// 排除纯方法词（GET/POST...）与纯数字段
		allUpper, allDigit := true, true
		for _, ch := range seg {
			if ch < 'A' || ch > 'Z' {
				allUpper = false
			}
			if ch < '0' || ch > '9' {
				allDigit = false
			}
		}
		if allUpper || allDigit {
			continue
		}
		counts["/"+seg]++
	}

	type kv struct {
		path string
		n    int
	}
	var list []kv
	for p, n := range counts {
		if n < MinPrefixCount {
			continue
		}
		list = append(list, kv{p, n})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].path < list[j].path
	})
	if len(list) > max {
		list = list[:max]
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		out = append(out, e.path)
	}
	return out
}
