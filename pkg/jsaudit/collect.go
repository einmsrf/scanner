package jsaudit

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/einmsrf/scanner/pkg/httpx"
)

// 默认上限（DESIGN.md 第 7.1 节：JS ≤30/目标，单文件 ≤2MB）。
const (
	DefaultMaxJS      = 30
	DefaultMaxBody    = 2 << 20 // 2MB
	DefaultMaxPages   = 8       // 深度 1 爬取的页面数上限
	DefaultMaxInline  = 12      // 内联脚本数上限
	maxSourceMapBytes = 8 << 20 // sourcemap 可能远大于 JS
)

// Asset 是一份被审计的代码。
type Asset struct {
	URL       string // 外部 JS 为该文件 URL；内联为其所属页面 URL
	PageURL   string // 发现它的页面
	Source    string // external | inline | sourcemap
	Code      []byte
	Size      int64
	Truncated bool
	Note      string
}

// Options 控制收集行为。
type Options struct {
	MaxJS          int
	MaxPages       int
	MaxInline      int
	MaxBody        int64
	SkipSourceMaps bool
	SkipInline     bool
	SkipDepthOne   bool // 只分析落地页，不爬深度 1
}

func (o Options) withDefaults() Options {
	if o.MaxJS <= 0 {
		o.MaxJS = DefaultMaxJS
	}
	if o.MaxPages <= 0 {
		o.MaxPages = DefaultMaxPages
	}
	if o.MaxInline <= 0 {
		o.MaxInline = DefaultMaxInline
	}
	if o.MaxBody <= 0 {
		o.MaxBody = DefaultMaxBody
	}
	return o
}

// Collection 是收集结果。
type Collection struct {
	Assets    []Asset
	PageURLs  []string // 实际分析过的页面
	Requests  int
	Notes     []string
	Truncated bool
}

var (
	hrefRe      = regexp.MustCompile(`(?i)href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	scriptSrcRe = regexp.MustCompile(`(?is)<script\b[^>]*?src\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	scriptTagRe = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)
	jsonTypeRe  = regexp.MustCompile(`(?i)type\s*=\s*["']?([a-z0-9/+.-]+)["']?`)
)

// skippedScriptTypes 是明确不是 JS 也不是配置数据的内联脚本类型。
var skippedScriptTypes = map[string]bool{
	"text/template":              true,
	"text/x-handlebars-template": true,
	"text/ng-template":           true,
	"text/html":                  true,
	"image/svg+xml":              true,
}

// Collect 从给定页面出发收集 JS：外部脚本、内联脚本、sourcemap。
// seeds 应是调用方已经请求过的页面响应（首页/base-path 落地页），不额外消耗请求。
func Collect(ctx context.Context, c *httpx.Client, origin string, seeds []*httpx.Response, opts Options) *Collection {
	opts = opts.withDefaults()
	col := &Collection{}
	origin = strings.TrimSuffix(origin, "/")

	pages := collectPages(ctx, c, origin, seeds, opts, col)

	// 提取脚本引用与内联脚本
	type scriptRef struct {
		raw  string
		page string
	}
	var (
		refs    []scriptRef
		inlines []Asset
		seenRef = map[string]bool{}
	)
	for _, p := range pages {
		if p == nil || len(p.Body) == 0 {
			continue
		}
		html := p.Text()
		for _, m := range scriptSrcRe.FindAllStringSubmatch(html, -1) {
			raw := firstNonEmptyGroup(m[1:])
			if raw == "" {
				continue
			}
			abs, ok := resolveURL(p.URL, raw)
			if !ok {
				continue
			}
			if seenRef[abs] {
				continue
			}
			seenRef[abs] = true
			refs = append(refs, scriptRef{raw: abs, page: p.URL})
		}
		if opts.SkipInline {
			continue
		}
		for _, m := range scriptTagRe.FindAllStringSubmatch(html, -1) {
			attrs, body := m[1], m[2]
			if strings.Contains(strings.ToLower(attrs), "src=") {
				continue // 外部脚本另行处理
			}
			if t := scriptType(attrs); skippedScriptTypes[t] {
				continue
			}
			if strings.TrimSpace(body) == "" {
				continue
			}
			if len(inlines) >= opts.MaxInline {
				col.Truncated = true
				col.Notes = append(col.Notes, "内联脚本数量达到上限，后续内联脚本未分析")
				break
			}
			inlines = append(inlines, Asset{
				URL:     p.URL,
				PageURL: p.URL,
				Source:  "inline",
				Code:    []byte(body),
				Size:    int64(len(body)),
			})
		}
	}

	// 外部 JS：数量上限内逐个下载
	fetched := 0
	for _, ref := range refs {
		if fetched >= opts.MaxJS {
			col.Truncated = true
			col.Notes = append(col.Notes, "JS 文件数量达到上限，其余未下载")
			break
		}
		if !budgetOK(c, col) {
			break
		}
		resp, err := c.Do(ctx, &httpx.Request{URL: ref.raw, MaxBody: opts.MaxBody})
		col.Requests++
		if err != nil {
			if errors.Is(err, httpx.ErrBudgetExceeded) {
				col.Truncated = true
				col.Notes = append(col.Notes, "请求预算用尽，部分 JS 未下载")
				break
			}
			col.Notes = append(col.Notes, "下载失败 "+ref.raw+": "+err.Error())
			continue
		}
		if resp.Status >= 400 || len(resp.Body) == 0 {
			continue
		}
		fetched++
		col.Assets = append(col.Assets, Asset{
			URL:       resp.URL,
			PageURL:   ref.page,
			Source:    "external",
			Code:      resp.Body,
			Size:      int64(len(resp.Body)),
			Truncated: resp.Truncated,
		})
		// sourcemap 能还原源码，信息量远大于混淆后的 JS
		if !opts.SkipSourceMaps {
			if a, ok := fetchSourceMap(ctx, c, resp.URL, col, opts); ok {
				col.Assets = append(col.Assets, a)
			}
		}
	}
	col.Assets = append(col.Assets, inlines...)
	return col
}

// collectPages 返回要分析的页面：seeds + 同域深度 1 的链接页面。
func collectPages(ctx context.Context, c *httpx.Client, origin string, seeds []*httpx.Response, opts Options, col *Collection) []*httpx.Response {
	pages := make([]*httpx.Response, 0, len(seeds)+opts.MaxPages)
	seen := map[string]bool{}
	for _, s := range seeds {
		if s == nil {
			continue
		}
		pages = append(pages, s)
		col.PageURLs = append(col.PageURLs, s.URL)
		seen[normalizeURL(s.URL)] = true
	}
	if opts.SkipDepthOne || len(seeds) == 0 {
		return pages
	}

	// 从种子页抽取同域链接
	var links []string
	linkSeen := map[string]bool{}
	for _, s := range seeds {
		if s == nil || !s.IsHTML() {
			continue
		}
		for _, m := range hrefRe.FindAllStringSubmatch(s.Text(), -1) {
			raw := firstNonEmptyGroup(m[1:])
			if raw == "" || strings.HasPrefix(raw, "#") {
				continue
			}
			abs, ok := resolveURL(s.URL, raw)
			if !ok || !sameHost(abs, origin) {
				continue
			}
			if isStaticURL(abs) {
				continue
			}
			key := normalizeURL(abs)
			if seen[key] || linkSeen[key] {
				continue
			}
			linkSeen[key] = true
			links = append(links, abs)
		}
	}

	crawled := 0
	for _, l := range links {
		if crawled >= opts.MaxPages {
			col.Truncated = true
			col.Notes = append(col.Notes, "深度 1 页面数达到上限，其余未爬取")
			break
		}
		if !budgetOK(c, col) {
			break
		}
		resp, err := c.Get(ctx, l)
		col.Requests++
		if err != nil {
			if errors.Is(err, httpx.ErrBudgetExceeded) {
				col.Truncated = true
				col.Notes = append(col.Notes, "请求预算用尽，部分页面未爬取")
				break
			}
			continue
		}
		if resp.Status >= 400 || !resp.IsHTML() {
			continue
		}
		crawled++
		pages = append(pages, resp)
		col.PageURLs = append(col.PageURLs, resp.URL)
		seen[normalizeURL(resp.URL)] = true
	}
	return pages
}

// fetchSourceMap 尝试请求 <js>.map，成功则把 sourcesContent 拼成一份可分析代码。
func fetchSourceMap(ctx context.Context, c *httpx.Client, jsURL string, col *Collection, opts Options) (Asset, bool) {
	if !budgetOK(c, col) {
		return Asset{}, false
	}
	mapURL := jsURL + ".map"
	resp, err := c.Do(ctx, &httpx.Request{URL: mapURL, MaxBody: maxSourceMapBytes})
	col.Requests++
	if err != nil || resp.Status >= 400 || len(resp.Body) == 0 {
		return Asset{}, false
	}
	var sm struct {
		Sources        []string `json:"sources"`
		SourcesContent []string `json:"sourcesContent"`
	}
	if err := json.Unmarshal(resp.Body, &sm); err != nil {
		return Asset{}, false
	}
	if len(sm.SourcesContent) == 0 {
		// 只有文件名没有源码，信息量有限，不单独作为分析目标
		return Asset{}, false
	}
	var b strings.Builder
	for i, src := range sm.SourcesContent {
		if strings.TrimSpace(src) == "" {
			continue
		}
		name := ""
		if i < len(sm.Sources) {
			name = sm.Sources[i]
		}
		b.WriteString("// source: ")
		b.WriteString(name)
		b.WriteString("\n")
		b.WriteString(src)
		b.WriteString("\n")
	}
	if b.Len() == 0 {
		return Asset{}, false
	}
	code := b.String()
	return Asset{
		URL:     mapURL,
		PageURL: jsURL,
		Source:  "sourcemap",
		Code:    []byte(code),
		Size:    int64(len(code)),
		Note:    "由 .js.map 还原的源码",
	}, true
}

// budgetOK 判断请求预算是否还够用。
func budgetOK(c *httpx.Client, col *Collection) bool {
	if c.Remaining() > 0 {
		return true
	}
	col.Truncated = true
	col.Notes = append(col.Notes, "目标请求预算已用尽，JS 收集提前结束")
	return false
}

// resolveURL 把页面里的相对/协议相对/被转义 URL 解析成绝对 URL。
// 处理 `//static/js/x.js`（协议相对）与 `\/\/static/js/x.js`（JS 里转义的双斜杠）。
func resolveURL(pageURL, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	// 去掉 JS 字符串里的转义斜杠
	raw = strings.ReplaceAll(raw, `\/`, "/")
	low := strings.ToLower(raw)
	if strings.HasPrefix(low, "data:") || strings.HasPrefix(low, "javascript:") ||
		strings.HasPrefix(low, "mailto:") || strings.HasPrefix(low, "blob:") ||
		strings.HasPrefix(low, "about:") {
		return "", false
	}
	// 双斜杠开头有两种可能：协议相对（//cdn.example.com/x.js）或写坏的站内
	// 绝对路径（//static/js/x.js）。按首段是否像主机名判别，后者归一化为
	// /static/js/x.js（DESIGN.md 第 7.1 节要求处理这种畸形写法）。
	if strings.HasPrefix(raw, "//") {
		rest := raw[2:]
		seg := rest
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			seg = rest[:i]
		}
		if !looksLikeHost(seg) {
			raw = "/" + rest
		}
	}
	base, err := url.Parse(pageURL)
	if err != nil {
		return "", false
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	abs := base.ResolveReference(ref)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return "", false
	}
	if abs.Host == "" {
		return "", false
	}
	abs.Fragment = ""
	return abs.String(), true
}

// looksLikeHost 判断 URL 的首段是否像主机名（而非被写坏的路径首段）。
func looksLikeHost(seg string) bool {
	if seg == "" {
		return false
	}
	if strings.EqualFold(seg, "localhost") {
		return true
	}
	if strings.Contains(seg, ":") { // host:port
		return true
	}
	// 含点且点不在首尾 → 像域名或 IP
	if i := strings.IndexByte(seg, '.'); i > 0 && i < len(seg)-1 {
		return true
	}
	return false
}

// sameHost 比较两个 URL 的主机名（忽略端口，便于同域 CDN 场景）。
func sameHost(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(ua.Hostname(), ub.Hostname())
}

// normalizeURL 用于去重：忽略 fragment。
func normalizeURL(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	return s
}

// scriptType 取内联脚本的 type 属性。
func scriptType(attrs string) string {
	m := jsonTypeRe.FindStringSubmatch(attrs)
	if m == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(m[1]))
}

// firstNonEmptyGroup 返回捕获组里第一个非空值。
func firstNonEmptyGroup(groups []string) string {
	for _, g := range groups {
		if s := strings.TrimSpace(g); s != "" {
			return s
		}
	}
	return ""
}
