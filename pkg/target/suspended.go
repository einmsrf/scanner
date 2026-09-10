package target

import (
	"net/url"
	"strings"

	"github.com/einmsrf/scanner/pkg/httpx"
)

// suspendedURLHints 是 URL 里出现即高度可疑的片段（暂停/维护页的常见文件名）。
var suspendedURLHints = []string{
	"offtime", "off-line", "offline.html", "maintenance", "maintain.html",
	"closed.html", "suspend", "paused.html",
}

// suspendedTextMarkers 是页面正文/标题里的"暂停服务"特征文案。
// 只收足够具体的短语，避免把普通的 5xx 错误页误判成"暂停服务"。
var suspendedTextMarkers = []string{
	"系统暂停访问", "暂停访问", "暂停服务", "服务已暂停", "系统维护中",
	"网站维护中", "正在维护", "正在进行维护", "系统升级中", "业务暂停",
	"本系统暂停", "临时维护",
	"site under maintenance", "under maintenance", "site maintenance",
	"scheduled maintenance", "temporarily unavailable", "temporarily out of service",
	"service is temporarily unavailable", "we'll be back soon", "we will be back soon",
	"service suspended",
}

// SuspensionInfo 描述"目标处于暂停/维护状态"的判定结果。
type SuspensionInfo struct {
	Suspended bool
	Reason    string // 命中的依据，用于报告展示
}

// DetectSuspended 判断落地页是否是"暂停访问/维护中"页面。
//
// 背景（DESIGN.md 第 10 节实战修订）：案例 180.101.238.250:19094 夜间扫描只拿到
// offtime.html，真实业务 JS 一个都没抓到。若不标注，使用者会把"暂停页"的稀疏结果
// 误读成"目标没问题"。
//
// 判定只看落地页的 URL 与正文特征；仅在标题或正文前 8KB 内命中才算，
// 以免把正文深处的无关文案当成暂停页。
func DetectSuspended(resp *httpx.Response) SuspensionInfo {
	if resp == nil {
		return SuspensionInfo{}
	}
	// URL 特征：暂停页通常有固定文件名
	if u, err := url.Parse(resp.URL); err == nil {
		full := strings.ToLower(u.Path + "?" + u.RawQuery)
		for _, hint := range suspendedURLHints {
			if strings.Contains(full, hint) {
				return SuspensionInfo{Suspended: true, Reason: "落地页 URL 含 " + hint}
			}
		}
	}

	// 正文特征：标题 + 正文前 8KB
	head := resp.Body
	if len(head) > 8192 {
		head = head[:8192]
	}
	low := strings.ToLower(string(head))
	if title := strings.ToLower(ExtractRawTitle(string(head))); title != "" {
		for _, m := range suspendedTextMarkers {
			if strings.Contains(title, strings.ToLower(m)) {
				return SuspensionInfo{Suspended: true, Reason: "页面标题含「" + m + "」"}
			}
		}
	}
	for _, m := range suspendedTextMarkers {
		if strings.Contains(low, strings.ToLower(m)) {
			return SuspensionInfo{Suspended: true, Reason: "页面内容含「" + m + "」"}
		}
	}
	return SuspensionInfo{}
}

// ExtractRawTitle 从 HTML 里取 <title> 文本（大小写不敏感，失败返回空串）。
// 与 report.ExtractTitle 的区别：不截断、不做单行压平，只用于特征匹配。
func ExtractRawTitle(html string) string {
	low := strings.ToLower(html)
	i := strings.Index(low, "<title")
	if i < 0 {
		return ""
	}
	j := strings.IndexByte(low[i:], '>')
	if j < 0 {
		return ""
	}
	rest := html[i+j+1:]
	k := strings.Index(strings.ToLower(rest), "</title>")
	if k < 0 {
		return ""
	}
	return rest[:k]
}
