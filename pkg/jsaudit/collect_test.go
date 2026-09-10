package jsaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/einmsrf/scanner/pkg/httpx"
)

func mustClient(t *testing.T, maxReq int) *httpx.Client {
	t.Helper()
	c, err := httpx.New(httpx.Options{QPS: -1, Timeout: 3e9, MaxRequests: maxReq})
	if err != nil {
		t.Fatalf("httpx.New: %v", err)
	}
	return c
}

func TestResolveURLHandlesProtocolRelativeAndEscapes(t *testing.T) {
	page := "https://example.com/app/index.html"
	cases := []struct {
		raw  string
		want string
		ok   bool
	}{
		{"/static/app.js", "https://example.com/static/app.js", true},
		{"//static/js/app.js", "https://example.com/static/js/app.js", true},
		{`\/\/static\/js\/app.js`, "https://example.com/static/js/app.js", true},
		{"app.js", "https://example.com/app/app.js", true},
		{"https://cdn.example.com/x.js", "https://cdn.example.com/x.js", true},
		{"data:image/png;base64,AAA", "", false},
		{"javascript:void(0)", "", false},
		{"mailto:a@b.com", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := resolveURL(page, c.raw)
		if ok != c.ok {
			t.Errorf("resolveURL(%q) ok = %v, want %v", c.raw, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("resolveURL(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestSameHost(t *testing.T) {
	if !sameHost("https://example.com/a.js", "https://example.com") {
		t.Error("同域应判定为真")
	}
	if !sameHost("https://example.com:8443/a.js", "http://example.com") {
		t.Error("端口不同但同主机名应判定为真")
	}
	if sameHost("https://cdn.example.com/a.js", "https://example.com") {
		t.Error("子域不同不应判定为同域")
	}
}

func TestCollectFindsExternalInlineAndSourceMap(t *testing.T) {
	src := "var a=1;\n//# sourceMappingURL=app.js.map\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head>
			<script src="/static/app.js"></script>
			<script src="//cdn.example.com/other.js"></script>
			<script>var inlineSecret={password:"Xk9#mQ2$vL7"};</script>
			<script type="text/template"><div>{{x}}</div></script>
		</head></html>`)
	})
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, src)
	})
	mux.HandleFunc("/static/app.js.map", func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(map[string]any{
			"sources":        []string{"src/secret.ts"},
			"sourcesContent": []string{"const key = \"" + fakeAWSKey + "\";\n"},
		})
		w.Write(b)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := mustClient(t, 100)
	defer c.Close()

	root, err := c.Get(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	col := Collect(context.Background(), c, srv.URL, []*httpx.Response{root}, Options{
		SkipDepthOne: true, // 跨域 CDN 不会被下载，避免依赖外部网络
	})

	var hasExternal, hasInline, hasSourceMap bool
	for _, a := range col.Assets {
		switch a.Source {
		case "external":
			if strings.HasSuffix(a.URL, "/static/app.js") {
				hasExternal = true
			}
		case "inline":
			hasInline = true
		case "sourcemap":
			hasSourceMap = true
		}
	}
	if !hasExternal {
		t.Error("未收集到外部 JS")
	}
	if !hasInline {
		t.Error("未收集到内联脚本")
	}
	if !hasSourceMap {
		t.Error("未收集到 sourcemap（sourcesContent 存在时应收录）")
	}

	// 内联脚本里的密码应被检出
	res := Extract(col.Assets, ExtractOptions{})
	var foundInline bool
	for _, f := range res.Findings {
		if f.RuleID == "assign-password" && f.Source == "inline" {
			foundInline = true
		}
	}
	if !foundInline {
		t.Error("内联脚本中的密码未被检出")
	}
	// sourcemap 还原出的源码里的 AK 应被检出
	var foundMap bool
	for _, f := range res.Findings {
		if f.RuleID == "aws-access-key-id" {
			foundMap = true
		}
	}
	if !foundMap {
		t.Error("sourcemap 还原源码中的 AK 未被检出")
	}
}

func TestCollectSkipsNonJSScriptTypes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html>
			<script type="text/template">var fake={password:"Xk9#mQ2$vL7"};</script>
			<script type="application/json">{"password":"Yk8#mQ2$vL8"}</script>
		</html>`)
	}))
	defer srv.Close()

	c := mustClient(t, 50)
	defer c.Close()
	root, _ := c.Get(context.Background(), srv.URL+"/")
	col := Collect(context.Background(), c, srv.URL, []*httpx.Response{root}, Options{SkipDepthOne: true})

	var templateFound, jsonFound bool
	for _, a := range col.Assets {
		if strings.Contains(string(a.Code), "Xk9#mQ2$vL7") {
			templateFound = true
		}
		if strings.Contains(string(a.Code), "Yk8#mQ2$vL8") {
			jsonFound = true
		}
	}
	if templateFound {
		t.Error("text/template 内联脚本不应被当作 JS 分析")
	}
	if !jsonFound {
		t.Error("application/json 内联数据应被分析（配置里可能含密钥）")
	}
}

func TestCollectDepthOneCrawlsSameDomainPages(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html>
			<a href="/page2">p2</a>
			<a href="https://other.example.org/ext">外部</a>
			<a href="/static/x.css">css</a>
		</html>`)
	})
	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><script>var s={password:"Xk9#mQ2$vL7"};</script></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := mustClient(t, 50)
	defer c.Close()
	root, _ := c.Get(context.Background(), srv.URL+"/")
	col := Collect(context.Background(), c, srv.URL, []*httpx.Response{root}, Options{})

	var crawled bool
	for _, p := range col.PageURLs {
		if strings.HasSuffix(p, "/page2") {
			crawled = true
		}
	}
	if !crawled {
		t.Errorf("未爬取同域深度 1 页面，PageURLs = %v", col.PageURLs)
	}
	for _, p := range col.PageURLs {
		if strings.Contains(p, "other.example.org") {
			t.Errorf("不应爬取外部域: %s", p)
		}
	}
}

func TestCollectRespectsMaxJS(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("<html>")
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&sb, `<script src="/j%d.js"></script>`, i)
	}
	sb.WriteString("</html>")
	html := sb.String()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			fmt.Fprint(w, html)
			return
		}
		fmt.Fprint(w, "var x=1;")
	}))
	defer srv.Close()

	c := mustClient(t, 100)
	defer c.Close()
	root, _ := c.Get(context.Background(), srv.URL+"/")
	col := Collect(context.Background(), c, srv.URL, []*httpx.Response{root}, Options{
		MaxJS: 3, SkipSourceMaps: true, SkipDepthOne: true,
	})

	external := 0
	for _, a := range col.Assets {
		if a.Source == "external" {
			external++
		}
	}
	if external != 3 {
		t.Errorf("external JS = %d, want 3（受 MaxJS 限制）", external)
	}
	if !col.Truncated {
		t.Error("Truncated = false, want true")
	}
}

func TestCollectTruncatesLargeJS(t *testing.T) {
	big := strings.Repeat("a", 5000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<html><script src="/big.js"></script></html>`)
			return
		}
		fmt.Fprint(w, big)
	}))
	defer srv.Close()

	c := mustClient(t, 50)
	defer c.Close()
	root, _ := c.Get(context.Background(), srv.URL+"/")
	col := Collect(context.Background(), c, srv.URL, []*httpx.Response{root}, Options{
		MaxBody: 100, SkipSourceMaps: true, SkipDepthOne: true,
	})
	if len(col.Assets) != 1 {
		t.Fatalf("assets = %d, want 1", len(col.Assets))
	}
	a := col.Assets[0]
	if len(a.Code) != 100 {
		t.Errorf("len(Code) = %d, want 100（按 MaxBody 截断）", len(a.Code))
	}
	if !a.Truncated {
		t.Error("Truncated = false, want true")
	}
}

func TestCollectStopsGracefullyWhenBudgetExhausted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<html>
				<script src="/a.js"></script><script src="/b.js"></script><script src="/c.js"></script>
			</html>`)
			return
		}
		fmt.Fprint(w, "var x=1;")
	}))
	defer srv.Close()

	// 预算只够 1 次请求：根页面已用掉，JS 一个都下不来
	c := mustClient(t, 1)
	defer c.Close()
	root, _ := c.Get(context.Background(), srv.URL+"/")
	col := Collect(context.Background(), c, srv.URL, []*httpx.Response{root}, Options{SkipSourceMaps: true, SkipDepthOne: true})

	if len(col.Assets) != 0 {
		t.Errorf("assets = %d, want 0（预算已用尽）", len(col.Assets))
	}
	if !col.Truncated {
		t.Error("Truncated = false, want true")
	}
	var noted bool
	for _, n := range col.Notes {
		if strings.Contains(n, "预算") {
			noted = true
		}
	}
	if !noted {
		t.Errorf("Notes 未说明预算耗尽: %v", col.Notes)
	}
}

func TestCollectSkipsFailedAndNon200JSPaths(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><script src="/missing.js"></script><script src="/ok.js"></script></html>`)
		case "/ok.js":
			fmt.Fprint(w, "var ok=1;")
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	c := mustClient(t, 50)
	defer c.Close()
	root, _ := c.Get(context.Background(), srv.URL+"/")
	col := Collect(context.Background(), c, srv.URL, []*httpx.Response{root}, Options{SkipSourceMaps: true, SkipDepthOne: true})
	if len(col.Assets) != 1 {
		t.Fatalf("assets = %d, want 1（404 的 JS 应跳过）", len(col.Assets))
	}
	if !strings.HasSuffix(col.Assets[0].URL, "/ok.js") {
		t.Errorf("URL = %q, want /ok.js", col.Assets[0].URL)
	}
}

func TestRunEndToEnd(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><script src="/app.js"></script></html>`)
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `
// 测试账号: testadmin / Test@123456
var cfg = {
  Authorization: "Basic YWRtaW46YWJjZEAxMjM0",
  apiKey: "wJalrXUtnFEMI/K7MDENGbPxRfiCYEXAMPL",
  host: "10.20.30.40",
  base: "https://svc.internal"
};
fetch("/api/v2/internal/users");
`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := mustClient(t, 100)
	defer c.Close()
	root, _ := c.Get(context.Background(), srv.URL+"/")

	rep := Run(context.Background(), c, srv.URL, []*httpx.Response{root}, RunOptions{
		Collect: Options{SkipSourceMaps: true, SkipDepthOne: true},
	})
	if len(rep.Assets) != 1 {
		t.Fatalf("assets = %d, want 1", len(rep.Assets))
	}
	if rep.Requests == 0 {
		t.Error("Requests = 0")
	}

	cats := map[Category]int{}
	for _, f := range rep.Findings {
		cats[f.Category]++
	}
	for _, want := range []Category{CatCredential, CatToken, CatInternal, CatComment} {
		if cats[want] == 0 {
			t.Errorf("缺少类别 %s 的检出（实际: %v）", want.Display(), cats)
		}
	}
	if len(rep.Endpoints) == 0 {
		t.Error("未提取到接口路径")
	}
	var hasAPI bool
	for _, e := range rep.Endpoints {
		if e.Path == "/api/v2/internal/users" {
			hasAPI = true
		}
	}
	if !hasAPI {
		t.Errorf("缺少接口 /api/v2/internal/users，实际 = %v", rep.Endpoints)
	}
	if rep.HighestSeverity() != SevHigh {
		t.Errorf("HighestSeverity = %v, want high", rep.HighestSeverity())
	}
	if len(rep.Snippets()) == 0 {
		t.Error("Snippets 为空，语义层无输入")
	}
}

func TestRunNeverRequestsDiscoveredEndpoints(t *testing.T) {
	// 铁律：只分析，绝不主动请求 JS 里发现的接口。
	var requested []string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><script src="/app.js"></script></html>`)
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `fetch("/api/admin/deleteAll"); axios.post("/api/internal/secret");`)
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		mux.ServeHTTP(w, r)
	}))
	defer srv.Close()

	c := mustClient(t, 100)
	defer c.Close()
	root, _ := c.Get(context.Background(), srv.URL+"/")
	rep := Run(context.Background(), c, srv.URL, []*httpx.Response{root}, RunOptions{
		Collect: Options{SkipSourceMaps: true, SkipDepthOne: true},
	})
	if len(rep.Endpoints) == 0 {
		t.Fatal("未提取到接口，测试无意义")
	}
	for _, p := range requested {
		if strings.HasPrefix(p, "/api/") {
			t.Errorf("违反铁律：主动请求了 JS 中发现的接口 %s（实际请求: %v）", p, requested)
		}
	}
}
