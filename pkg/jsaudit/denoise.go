package jsaudit

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

// ---------- vendor / 库文件识别 ----------

// vendorFileRe 匹配典型的第三方打包产物文件名。
// 依据实战 113 目标扫描结果：chunk.js.map、vendor.da4be07c.js.map、chunk-vendors.js、
// chunk-libs.a171f87c.js、moxie.min.js、plupload.full.min.js、swiper2.7.6.min.js、bootstrap.min.js
var vendorFileRe = regexp.MustCompile(`(?i)(^|[/.\-_])(vendor|vendors|chunk|chunks|libs|lib)([/.\-_]|$)`)

// vendorPathHints 是路径里出现即视为库文件的片段。
var vendorPathHints = []string{
	"lodash", "underscore", "jquery", "jquery-", "three.js", "three.min",
	"bootstrap", "swiper", "plupload", "moxie", "moment.min", "echarts",
	"element-ui", "elementui", "antd", "axios.min", "vue.min", "react.production",
	"polyfill", "core-js", "regenerator", "babel", "webpack",
}

// licenseHeaderMarkers 是库文件里的 license 头特征。命中即认为该文件内容以第三方库为主。
var licenseHeaderMarkers = []string{
	"mit license", "apache license", "bsd license", "isc license",
	"gnu general public license", "mozilla public license",
	"@license", "license: mit", "released under the mit license",
	"the mit license (mit)", "licensed under the apache license",
}

// knownLibraryNames 与 license 头组合出现时才判定为 vendor，降低误判。
var knownLibraryNames = []string{
	"lodash", "underscore", "jquery", "three.js", "mrdoob", "bootstrap",
	"moment.js", "axios", "vue.js", "react", "angular", "echarts", "swiper",
	"plupload", "moxie", "openjs foundation", "js foundation",
}

// IsVendorAsset 判断该 JS 是否为第三方库/打包 vendor 文件。
// 命中后调用方只跑高危规则，跳过内网信息、注释信息等低危类别。
func IsVendorAsset(rawURL, code string) bool { return isVendorAsset(rawURL, code) }

func isVendorAsset(rawURL, code string) bool {
	if u, err := url.Parse(rawURL); err == nil {
		name := strings.ToLower(u.Path)
		if vendorFileRe.MatchString(name) {
			return true
		}
		for _, hint := range vendorPathHints {
			if strings.Contains(name, hint) {
				return true
			}
		}
	}
	// 内容特征：license 头 + 已知库名同时出现
	head := code
	if len(head) > 4096 {
		head = head[:4096] // license 头一定在文件开头
	}
	low := strings.ToLower(head)
	var hasLicense, hasLib bool
	for _, m := range licenseHeaderMarkers {
		if strings.Contains(low, m) {
			hasLicense = true
			break
		}
	}
	if !hasLicense {
		return false
	}
	for _, n := range knownLibraryNames {
		if strings.Contains(low, n) {
			hasLib = true
			break
		}
	}
	return hasLib
}

// ---------- 注释 URL 过滤 ----------

// 实测结论（2026-09-10 晚，113 目标，277 条去重注释 URL）：
//   第三方域名 269 条，全部是库文档/规范/教程链接（ecma-international.org、whatwg.org、
//   stackoverflow.com、jsperf.com、fb.me、getbootstrap.com、underscorejs.org…）；
//   同站 1 条、内网 7 条——这 8 条才是有研判价值的目标自身信息
//   （例如 http://10.32.230.130:6080/arcgis/rest/services/）。
// 因此不再维护"公共文档域名黑名单"（永远列不全、且维护成本高），
// 改为高精度规则：**注释 URL 只保留同站、内网、或公网 IP 字面量**，其余一律丢弃。
// 降噪率从 66.8% 提升到 97.1%，且一条有效信息都没少。
// 裸公网 IP 例外：图书文档站不会用 IP，出现 IP 通常是目标自身的基础设施引用。

// internalHost 判断是否内网地址（内网 IP 或内网域名后缀）。
func internalHost(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" {
		return true
	}
	if ip := parseIPCandidate(host); ip != "" {
		return isPrivateIP(ip)
	}
	for _, suf := range []string{".internal", ".corp", ".intranet", ".lan", ".local"} {
		if strings.HasSuffix(host, suf) {
			return true
		}
	}
	return false
}

// CommentURLRelevant 判断注释里的 URL 是否有研判价值。
// 保留条件（任一）：内网地址、同站（含同父域）、公网 IP 字面量。
// 其余第三方域名按实测结论一律丢弃（全是库文档/规范/教程噪声）。
// pageHost 为当前页面主机名。
func CommentURLRelevant(rawURL, pageHost string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if internalHost(host) {
		return true
	}
	if pageHost != "" {
		trimmed := strings.TrimSuffix(pageHost, ".")
		if strings.EqualFold(host, trimmed) || sameSite(host, trimmed) {
			return true
		}
	}
	// 公网 IP 字面量：文档站不会用裸 IP，出现 IP 多是目标自身的基础设施引用
	return isIPv4(host)
}

// sameSite 判断两个主机名是否属于同一站点（父域相同）。
func sameSite(a, b string) bool {
	ra, rb := registrableDomain(a), registrableDomain(b)
	return ra != "" && ra == rb
}

// registrableDomain 取末两级作为近似注册域（不引入公共后缀列表依赖，
// 仅在注释 URL 去噪这种低风险场景使用）。
func registrableDomain(host string) string {
	parts := strings.Split(strings.TrimSuffix(host, "."), ".")
	if len(parts) < 2 {
		return host
	}
	// IP 不做父域合并
	if isIPv4(host) {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// parseIPCandidate 若 host 是 IP 字面量则返回其规范化形式，否则返回空串。
func parseIPCandidate(host string) string {
	h := strings.Trim(host, "[]")
	if net.ParseIP(h) != nil {
		return h
	}
	return ""
}

// isIPv4 判断是否为 IPv4 字面量。
func isIPv4(s string) bool {
	ip := net.ParseIP(strings.Trim(s, "[]"))
	return ip != nil && ip.To4() != nil
}

// isPrivateIP 判断是否为内网/回环/链路本地地址。
// net.IP.IsPrivate 覆盖 10/8、172.16/12、192.168/16。
func isPrivateIP(s string) bool {
	ip := net.ParseIP(strings.Trim(s, "[]"))
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// hostOf 取 URL 的主机名；解析失败返回空串。
func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
