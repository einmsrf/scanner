package fingerprint

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/einmsrf/scanner/pkg/httpx"
)

// linkTagRe 匹配 HTML 中的 <link ...> 标签，用于定位真实 favicon。
var linkTagRe = regexp.MustCompile(`(?is)<link\b[^>]*>`)

// attrRe 从标签中取出指定属性的值（单/双引号或无引号）。
func attrRe(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?is)\b` + name + `\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
}

var (
	relAttrRe  = attrRe("rel")
	hrefAttrRe = attrRe("href")
)

// FindIconURL 从落地页 HTML 中解析 favicon 的真实地址（<link rel="...icon...">），
// 解析不到时回退到站点根的 /favicon.ico。见 DESIGN.md 第 5.2 节第 2 层。
func FindIconURL(origin string, resp *httpx.Response) string {
	fallback := strings.TrimSuffix(origin, "/") + "/favicon.ico"
	if resp == nil || len(resp.Body) == 0 {
		return fallback
	}
	base, err := url.Parse(resp.URL)
	if err != nil {
		base, _ = url.Parse(strings.TrimSuffix(origin, "/") + "/")
	}
	// 优先 shortcut icon / icon，其次 apple-touch-icon。
	var best string
	for _, tag := range linkTagRe.FindAllString(resp.Text(), -1) {
		rel := firstGroup(relAttrRe, tag)
		if rel == "" {
			continue
		}
		rel = strings.ToLower(rel)
		if !strings.Contains(rel, "icon") {
			continue
		}
		href := firstGroup(hrefAttrRe, tag)
		if href == "" || strings.HasPrefix(href, "data:") {
			continue
		}
		ref, err := url.Parse(strings.TrimSpace(href))
		if err != nil {
			continue
		}
		abs := base.ResolveReference(ref).String()
		// apple-touch-icon 优先级低于普通 icon
		if strings.Contains(rel, "apple") && best != "" {
			continue
		}
		if best == "" || !strings.Contains(rel, "apple") {
			best = abs
		}
	}
	if best == "" {
		return fallback
	}
	return best
}

// firstGroup 返回第一个非空捕获组。
func firstGroup(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	for i := 1; i < len(m); i++ {
		if s := strings.TrimSpace(m[i]); s != "" {
			return s
		}
	}
	return ""
}

// attrPathRe 提取页面中出现的站内绝对路径：href/src/action 属性值和 JS 字符串字面量。
var attrPathRe = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["'](/[^"'?#\s]*)["']`)
var jsPathRe = regexp.MustCompile(`["'](/[A-Za-z0-9_\-./]{2,80})["']`)

// subdirStoplist 是明显与部署目录无关的静态资源目录，避免污染候选 base。
var subdirStoplist = map[string]bool{
	"static": true, "assets": true, "asset": true, "js": true, "css": true,
	"img": true, "images": true, "image": true, "fonts": true, "font": true,
	"media": true, "public": true, "favicon.ico": true, "index.html": true,
	"robots.txt": true, "manifest.json": true, "apple-touch-icon.png": true,
	"webpack": true, "chunk": true, "chunks": true, "dist": true, "build": true,
	"node_modules": true, "locales": true, "i18n": true, "lang": true,
}

// ExtractSubdirs 从落地页 HTML/JS 中提取站内一级目录，按出现频率排序取前 n 个。
// 这是 DESIGN.md 第 5.2 节第 3 层的“子目录候选”，用于应对部署目录被修改。
func ExtractSubdirs(pages []*httpx.Response, n int) []string {
	if n <= 0 {
		return nil
	}
	counts := map[string]int{}
	for _, p := range pages {
		if p == nil || len(p.Body) == 0 {
			continue
		}
		body := p.Text()
		for _, re := range []*regexp.Regexp{attrPathRe, jsPathRe} {
			for _, m := range re.FindAllStringSubmatch(body, -1) {
				if len(m) < 2 {
					continue
				}
				seg := firstSegment(m[1])
				if seg == "" || subdirStoplist[strings.ToLower(seg)] {
					continue
				}
				counts["/"+seg]++
			}
		}
	}
	if len(counts) == 0 {
		return nil
	}
	type kv struct {
		path string
		n    int
	}
	list := make([]kv, 0, len(counts))
	for p, c := range counts {
		list = append(list, kv{p, c})
	}
	// 频率降序；同频按路径字典序，保证结果稳定可复现。
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].path < list[j].path
	})
	if len(list) > n {
		list = list[:n]
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		out = append(out, e.path)
	}
	return out
}

// firstSegment 返回路径的第一段（不含斜杠）；根路径或空段返回空串。
func firstSegment(p string) string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return ""
	}
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[:i]
	}
	// 形如 foo.html / foo.do 的根级文件不是目录候选
	if strings.ContainsAny(p, ".") {
		return ""
	}
	return p
}
