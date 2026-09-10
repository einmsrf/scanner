package jsaudit

import (
	"strings"
	"testing"
)

// ---------- 端点语法校验 ----------

// 用例直接取自 2026-09-10 晚 113 目标真实扫描报告里被判定为脏数据的端点。
func TestEndpointDropReasonGarbage(t *testing.T) {
	cases := map[string]string{
		"GET":                     "method-word",
		"get":                     "method-word",
		"HEAD":                    "method-word",
		"POST":                    "method-word",
		"${e}":                    "template-residue",
		"/${filename}":            "template-residue",
		"image/${e.type}":         "template-residue",
		".concat(this.iconClass,": "concat-residue",
		"/errorCorrectLevel:":     "minified-tail",
		"+JSON.stringify(e)+":     "plus-residue",
		"/groups/:groupName+":     "plus-residue",
		"/:ids+.":                 "plus-residue",
		"//#line":                 "comment-or-regex-fragment",
		"//.*?/":                  "comment-or-regex-fragment",
		"//3n":                    "comment-or-regex-fragment",
		"image/png":               "mime-type",
		"image/svg+xml":           "mime-type",
		"http://example.com":      "bare-scheme",
		"https://cesium.com":      "bare-scheme",
		"data:image/png;base64,x": "scheme-not-http",
		"../":                     "relative-path",
		"example/url":             "relative-path",
		"/./":                     "empty-or-dot-path",
		"/":                       "too-short",
		"":                        "too-short",
	}
	for in, want := range cases {
		if got := EndpointDropReason(in); got != want {
			t.Errorf("EndpointDropReason(%q) = %q, want %q", in, got, want)
		}
	}
}

// 这些是合法端点，必须全部保留。重点是带 REST 路径参数与通配的路径——
// 实战里一刀切要求"只允许字母数字"会误删 124 个这类路径。
func TestEndpointDropReasonKeepsLegitimate(t *testing.T) {
	keep := []string{
		// Harbor 的 REST API（路径参数）
		"/namespaces/:tenantNamespace/tenants/:tenantName/pods",
		"/namespaces/:tenantNamespace/tenants/:tenantName/pods/:podName",
		"/namespaces/:tenantNamespace/tenants/:tenantName/metrics",
		"/buckets/:bucketName/admin*",
		"/buckets/:bucketName/browse*",
		"/settings/:option",
		// 问号卷的 REST 路由
		"/survey/design/:questionnaireId",
		"/survey/data/answers/:questionnaireId",
		"/notification-endpoints/add/:service",
		// 实测差点被 MIME 规则误删的真实路径
		"/video/record",
		"/video/stream",
		"/video/stream/delete",
		"/videoList",
		// 带查询串
		"/api/v1/orders?page=1",
		"/search?q=a+b",
		// 协议相对与绝对 URL（含路径）
		"//cdn.example.com/v2/list",
		"https://api.example.com/v2/items",
		// 普通业务路径
		"/api/v2/internal/users",
		"/controllerApi/1.0/userPermission/user/getUserPassword",
		"/system/user/list",
	}
	for _, p := range keep {
		if r := EndpointDropReason(p); r != "" {
			t.Errorf("EndpointDropReason(%q) = %q, want 保留（合法端点）", p, r)
		}
	}
}

func TestExtractFiltersGarbageEndpointsAndCountsReasons(t *testing.T) {
	code := `
fetch("GET"); fetch("post"); fetch("/api/v1/users");
var a = "image/png"; var b = "${e}"; var c = "/groups/x+"; var d = "/./";
`
	res := Extract([]Asset{codeAsset(code)}, ExtractOptions{})
	got := map[string]int{}
	for _, e := range res.Endpoints {
		got[e.Path] = e.Count
	}
	if _, bad := got["GET"]; bad {
		t.Error("方法词不应作为端点")
	}
	if _, bad := got["post"]; bad {
		t.Error("方法词不应作为端点")
	}
	if _, bad := got["image/png"]; bad {
		t.Error("MIME 值不应作为端点")
	}
	if _, bad := got["${e}"]; bad {
		t.Error("模板残渣不应作为端点")
	}
	if _, ok := got["/api/v1/users"]; !ok {
		t.Errorf("合法端点被误删，实际 = %v", got)
	}
	if res.Stats.FilteredEndpoints == 0 {
		t.Error("Stats.FilteredEndpoints 应记录被剔除数量")
	}
	if len(res.Stats.EndpointDropReasons) == 0 {
		t.Error("Stats.EndpointDropReasons 应记录剔除原因分布")
	}
	t.Logf("剔除 %d 条，原因分布: %v", res.Stats.FilteredEndpoints, res.Stats.EndpointDropReasons)
}

// ---------- vendor 文件识别 ----------

func TestIsVendorAssetByFilename(t *testing.T) {
	cases := []string{
		"http://x/static/js/17.0a3f7b0d.chunk.js.map",
		"https://x/index/js/vendor.da4be07dc3342d7216a6.js.map",
		"https://x/index/js/vendor.da4be07dc3342d7216a6.js",
		"http://yhtipipc.com/static/js/chunk-vendors.js?v=1",
		"https://114.55.42.234/static/js/chunk-libs.a171f87c.js",
		"https://oa.x/Cloud/JavaScript/plupload-2.1.2/moxie.min.js",
		"https://oa.x/Cloud/JavaScript/plupload-2.1.2/plupload.full.min.js",
		"https://member.x/jquery/swiper/swiper2.7.6.min.js",
		"https://www.x/assets/12309/js/bootstrap.min.js",
	}
	for _, u := range cases {
		if !IsVendorAsset(u, "") {
			t.Errorf("IsVendorAsset(%q) = false, want true", u)
		}
	}
}

func TestIsVendorAssetByLicenseHeader(t *testing.T) {
	code := `/**
 * @license
 * Lodash <https://lodash.com/>
 * Copyright OpenJS Foundation and other contributors <https://openjsf.org/>
 * Released under the MIT license <https://lodash.com/license>
 */
var _ = {};`
	if !IsVendorAsset("https://x/app.js", code) {
		t.Error("含 license 头 + 已知库名应判定为 vendor")
	}
	// 只有 license 头没有库名 → 不判定（避免把自研代码误判）
	if IsVendorAsset("https://x/app.js", "// MIT License\nvar a = 1;") {
		t.Error("仅 license 头不应判定为 vendor")
	}
}

func TestIsVendorAssetRejectsAppBundles(t *testing.T) {
	// 应用自身的入口包不是 vendor，必须照常跑全部规则
	for _, u := range []string{
		"http://x/umi.22bab870.js",
		"http://x/assets/index.d0fa5640.js",
		"http://x/yhfxfh-qd/js/util/util_config.js",
		"https://8.152.219.200/index/js/app.9fdfb601d8ebd43c2151.js",
	} {
		if IsVendorAsset(u, "var app=1;") {
			t.Errorf("IsVendorAsset(%q) = true, want false（应用自身包不应被当 vendor）", u)
		}
	}
}

// vendor 文件只跑高危规则：低危/中危规则应被跳过。
func TestVendorAssetsOnlyRunHighSeverityRules(t *testing.T) {
	// 一份"库文件"：含 license 头 + 库名，同时含内网 IP（低危）、注释信息（低危）、
	// 密码赋值（高危）、AK（高危）
	code := `/**
 * @license Released under the MIT license <https://lodash.com/license>
 * Copyright OpenJS Foundation
 */
var cfg = { password: "Xk9#mQ2$vL7", key: "` + fakeAWSKey + `", host: "10.20.30.40" };
// 测试账号: admin / Password123
`
	res := Extract([]Asset{{
		URL: "https://x/static/js/vendor.abc123.js", Source: "external", Code: []byte(code),
	}}, ExtractOptions{})

	var cats = map[Category]int{}
	for _, f := range res.Findings {
		cats[f.Category]++
		if f.Severity != SevHigh {
			t.Errorf("vendor 文件不应产出非高危发现: %s %s (%s)", f.Category.Display(), f.Severity, f.RuleID)
		}
	}
	if cats[CatCredential] == 0 {
		t.Error("vendor 文件仍应产出高危的硬编码凭证")
	}
	if cats[CatCloudKey] == 0 {
		t.Error("vendor 文件仍应产出高危的云 AK/SK")
	}
	if cats[CatInternal] != 0 {
		t.Error("vendor 文件不应产出低危的内网信息")
	}
	if cats[CatComment] != 0 {
		t.Error("vendor 文件不应产出低危的注释信息")
	}
}

func TestNonVendorAssetsRunAllRules(t *testing.T) {
	code := `var cfg = { password: "Xk9#mQ2$vL7", host: "10.20.30.40" };
// 测试账号: admin / Password123`
	res := Extract([]Asset{{
		URL: "https://x/assets/index.d0fa5640.js", Source: "external", Code: []byte(code),
	}}, ExtractOptions{})
	var cats = map[Category]int{}
	for _, f := range res.Findings {
		cats[f.Category]++
	}
	if cats[CatInternal] == 0 || cats[CatComment] == 0 {
		t.Errorf("应用自身包应跑全部规则，实际类别 = %v", cats)
	}
}

// ---------- 注释 URL 过滤 ----------

func TestCommentURLRelevantDropsPublicDocDomains(t *testing.T) {
	// 全部取自真实报告的噪声样本
	noise := []string{
		"http://www.w3.org/2000/svg",
		"http://www.w3.org/1999/xhtml",
		"http://www.w3.org/1998/Math/MathML",
		"https://lodash.com/license",
		"https://openjsf.org/",
		"http://underscorejs.org/LICENSE",
		"http://jcgt.org/published/0003/02/01/",
		"https://graphics.stanford.edu/papers/envmap/envmap.pdf",
		"http://developer.download.nvidia.com/cg/atan2.html",
		"https://knarkowicz.wordpress.com/2016/01/06/aces-filmic-tone-mapping-curve/",
		"https://github.com/mrdoob/three.js",
		"https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js",
		"https://fonts.googleapis.com/css?family=Roboto",
		"http://29a.ch/2012/7/19/webgl-terrain-rendering-water-fog",
	}
	for _, u := range noise {
		if CommentURLRelevant(u, "app.example.com") {
			t.Errorf("CommentURLRelevant(%q) = true, want false（公共文档域名应丢弃）", u)
		}
	}
}

func TestCommentURLRelevantKeepsActionable(t *testing.T) {
	page := "app.example.com"
	keep := []string{
		// 同域 / 同站
		"http://app.example.com/admin/doc",
		"https://api.example.com/docs",
		// 内网
		"http://wiki.internal.corp/sec",
		"http://10.20.30.40/wiki",
		"http://192.168.1.10:8080/doc",
		"http://172.16.5.5/manual",
		"http://svc.internal/",
		"http://portal.local/",
		"http://localhost:8080/api",
		// 公网 IP 字面量（文档站不会用裸 IP，出现 IP 多是目标自身基础设施）
		"http://39.97.196.199",
		"http://39.97.196.199:8080/api",
		"http://114.55.42.234/static/js/app.js",
	}
	for _, u := range keep {
		if !CommentURLRelevant(u, page) {
			t.Errorf("CommentURLRelevant(%q) = false, want true（有研判价值应保留）", u)
		}
	}
}

// 第三方域名（无论是否在文档站名单里）一律丢弃：
// 实测 113 目标里 269 条第三方注释 URL 全部是库文档/规范/教程噪声。
func TestCommentURLRelevantDropsAllThirdParty(t *testing.T) {
	thirdParty := []string{
		"https://popper.js.org/docs/v2/virtual-elements/",
		"https://mui.com/components/menus/",
		"https://material.io/design/typography/the-type-system.html",
		"https://caniuse.com/#search=multicolumn",
		"http://reactcommunity.org/react-transition-group/transition/",
		"https://bugs.webkit.org/show_bug.cgi?id=182678",
		"http://jsperf.com/array-join-vs-for",
		"http://fb.me/prop-types-in-prod",
		"http://www.matts411.com/post/internet-explorer-9-oninput/",
		"https://ops.partner-company.cn/runbook",
	}
	for _, u := range thirdParty {
		if CommentURLRelevant(u, "oa.hengyu.cn") {
			t.Errorf("CommentURLRelevant(%q) = true, want false（第三方域名一律丢弃）", u)
		}
	}
}

// 同站判定覆盖"自己的另一个子域"（应用常见：页面在 www，接口在 api）。
func TestCommentURLRelevantKeepsSameRegisteredDomain(t *testing.T) {
	page := "oa.hengyu.cn"
	for _, u := range []string{
		"https://api.hengyu.cn/v1/docs",
		"http://admin.oa.hengyu.cn/",
		"https://oa.hengyu.cn/admin",
	} {
		if !CommentURLRelevant(u, page) {
			t.Errorf("CommentURLRelevant(%q, %q) = false, want true（同站应保留）", u, page)
		}
	}
}

func TestExtractCommentURLFiltering(t *testing.T) {
	code := `
/* w3.org 命名空间与库 license 链接，属噪声 */
// 参见 http://www.w3.org/2000/svg 与 https://lodash.com/license
// 内部文档 http://wiki.internal.corp/sec
// 同域后台 https://oa.hengyu.cn/admin
`
	res := Extract([]Asset{{
		URL: "https://oa.hengyu.cn/app.js", Source: "external", Code: []byte(code),
	}}, ExtractOptions{})

	var urls []string
	for _, f := range res.Findings {
		if f.RuleID == "comment-url" {
			urls = append(urls, f.Value)
		}
	}
	joined := strings.Join(urls, " ")
	if strings.Contains(joined, "w3.org") || strings.Contains(joined, "lodash.com") {
		t.Errorf("公共文档域名应被过滤，实际保留: %v", urls)
	}
	if !strings.Contains(joined, "wiki.internal.corp") {
		t.Errorf("内网地址应保留，实际: %v", urls)
	}
	if !strings.Contains(joined, "oa.hengyu.cn") {
		t.Errorf("同域地址应保留，实际: %v", urls)
	}
	t.Logf("保留的注释地址: %v", urls)
}
