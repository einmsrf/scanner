package jsaudit

import (
	"regexp"
	"strings"
)

// 端点脏数据判定。采用**定点黑名单**而不是白名单正则：
// 实测 907 个去重端点里如果要求"只允许字母数字"，会误删 124 个合法端点
// （Harbor 的 /namespaces/:tenantNamespace/tenants/:tenantName/pods、
// /buckets/:bucketName/admin*、/survey/design/:questionnaireId 等），
// 而带 `:`（REST 路径参数）与 `*`（通配）的路径恰恰是研判重点。

var methodWordRe = regexp.MustCompile(`(?i)^/?(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)$`)

// mimeTypeRe 匹配 MIME 值。注意实测这些值**没有前导斜杠**（image/png、image/svg+xml），
// 若要求前导斜杠会把 /video/record、/video/stream 这类真实路径误删。
var mimeTypeRe = regexp.MustCompile(`^(application|text|image|audio|video|font|multipart|message|model|chemical)/[a-z0-9.+-]+$`)

// illegalPathChars 是路径里不该出现的字符（出现即为字符串/模板残渣）。
const illegalPathChars = " \t\n\r\"'<>`\\"

// EndpointDropReason 返回该端点被剔除的原因；返回空串表示是合法端点。
func EndpointDropReason(p string) string {
	if len(p) < 2 {
		return "too-short"
	}
	if methodWordRe.MatchString(p) {
		return "method-word"
	}
	// 模板字面量残渣：`/foo/${bar}`、反引号、反斜杠
	if strings.Contains(p, "${") || strings.ContainsAny(p, "`\\") {
		return "template-residue"
	}
	// 压缩代码的字符串拼接：`"/groups/"+name+"/x"` 会被切成 `+name+`
	if strings.Contains(p, ".concat(") {
		return "concat-residue"
	}
	// 尾部残留符号：`/errorCorrectLevel:`、`/x,`
	if strings.HasSuffix(p, ",") || strings.HasSuffix(p, ":") {
		return "minified-tail"
	}
	// MIME 值（实测无前导斜杠：image/png、image/svg+xml）。必须早于 plus-residue 判定，
	// 否则 image/svg+xml 会被误标为字符串拼接残渣
	if mimeTypeRe.MatchString(p) {
		return "mime-type"
	}
	// 含 `+` 但不在查询串里 → 上游是字符串拼接，路径不完整
	if strings.Contains(p, "+") && !strings.Contains(p, "?") {
		return "plus-residue"
	}
	if strings.ContainsAny(p, illegalPathChars) {
		return "illegal-char"
	}
	// 协议相对：`//cdn.example.com/x` 合法；`//#line`、`//.*?/` 是注释/正则碎片
	if strings.HasPrefix(p, "//") {
		if !looksLikeHost(p[2:]) {
			return "comment-or-regex-fragment"
		}
		return ""
	}
	// 绝对 URL：必须有路径才算"接口"
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		rest := p[strings.Index(p, "://")+3:]
		if rest == "" || !strings.Contains(rest, "/") {
			return "bare-scheme"
		}
		return ""
	}
	// 其它 scheme（data:、javascript:、blob: 等）：第一个 `:` 出现在第一个 `/` 之前
	if i := strings.IndexByte(p, '/'); i >= 0 {
		if j := strings.IndexByte(p, ':'); j >= 0 && j < i {
			return "scheme-not-http"
		}
	}
	// 相对路径语义不明（相对于什么基址不确定），不作为接口展示
	if !strings.HasPrefix(p, "/") {
		return "relative-path"
	}
	if onlyDotsOrSlashes(p) {
		return "empty-or-dot-path"
	}
	return ""
}

// onlyDotsOrSlashes 判断路径是否只由 . 和 / 组成（`/`、`/./`、`/../`）。
func onlyDotsOrSlashes(p string) bool {
	if p == "" {
		return true
	}
	for i := 0; i < len(p); i++ {
		if p[i] != '.' && p[i] != '/' {
			return false
		}
	}
	return true
}

// looksLikeHostSegment 见 collect.go 的 looksLikeHost；此处仅用于首段判断。
func looksLikeHostSegment(rest string) bool {
	seg := rest
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		seg = rest[:i]
	}
	return looksLikeHost(seg)
}
