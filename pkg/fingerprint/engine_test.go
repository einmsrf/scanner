package fingerprint

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/einmsrf/scanner/pkg/httpx"
)

func testLib(rules ...Rule) *Library {
	return &Library{Count: len(rules), Rules: rules, Source: "test"}
}

func wordRule(id, path, word string) Rule {
	return Rule{
		ID: id, Name: id, Paths: []string{path},
		Matchers: []Matcher{{Type: MatcherWord, Value: []string{word}}},
	}
}

func TestParseLibraryFiltersInvalidRules(t *testing.T) {
	data := []byte(`{"count":0,"rules":[
		{"id":"ok","name":"ok","paths":["/"],"matchers":[{"type":"word","value":["x"]}]},
		{"id":"","paths":["/"],"matchers":[{"type":"word","value":["x"]}]},
		{"id":"nomatcher","paths":["/"]},
		{"id":"nopaths","matchers":[{"type":"word","value":["x"]}]}
	]}`)
	lib, err := ParseLibrary(data)
	if err != nil {
		t.Fatalf("ParseLibrary: %v", err)
	}
	if len(lib.Rules) != 2 {
		t.Fatalf("rules = %d, want 2（空 ID 与无 matcher 被剔除）", len(lib.Rules))
	}
	if lib.Count != 2 {
		t.Errorf("Count = %d, want 2", lib.Count)
	}
	// 缺 paths 的规则应补成 "/"
	for _, r := range lib.Rules {
		if r.ID == "nopaths" && (len(r.Paths) != 1 || r.Paths[0] != "/") {
			t.Errorf("nopaths.Paths = %v, want [/]", r.Paths)
		}
	}
}

func TestParseLibraryEmptyErrors(t *testing.T) {
	if _, err := ParseLibrary([]byte(`{"rules":[]}`)); err == nil {
		t.Error("空指纹库应报错")
	}
	if _, err := ParseLibrary(nil); err == nil {
		t.Error("nil 应报错")
	}
	if _, err := ParseLibrary([]byte(`not json`)); err == nil {
		t.Error("非法 JSON 应报错")
	}
}

func TestEngineLayersRootWordAndHeader(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("X-Powered-By", "PHP/7.4")
			fmt.Fprint(w, "<html><title>nacos</title></html>")
			return
		}
		w.WriteHeader(404)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	lib := testLib(
		wordRule("body-rule", "/", "<title>nacos</title>"),
		Rule{ID: "header-rule", Name: "header-rule", Paths: []string{"/"},
			Matchers: []Matcher{{Type: MatcherWord, Part: PartHeader, CI: true, Value: []string{"x-powered-by: php"}}}},
		Rule{ID: "regex-rule", Name: "regex-rule", Paths: []string{"/"},
			Matchers: []Matcher{{Type: MatcherRegex, CI: true, Value: []string{`<title[^>]*>nacos</title>`}}}},
	)
	e := NewEngine(lib)
	c := mustClient(t)
	defer c.Close()

	res, err := e.Scan(context.Background(), c, Input{Origin: srv.URL}, Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	got := map[string]string{}
	for _, m := range res.Matches {
		got[m.Rule.ID] = m.Via
	}
	for _, id := range []string{"body-rule", "header-rule", "regex-rule"} {
		if _, ok := got[id]; !ok {
			t.Errorf("未命中 %s；实际命中 %v", id, got)
		}
	}
	if got["body-rule"] != "landing" {
		t.Errorf("body-rule Via = %q, want landing", got["body-rule"])
	}
}

func TestEngineMatchesPathRuleAtLandingDir(t *testing.T) {
	// 真实入口在 /oa/，根路径 302 过去（设计第 1 层）。
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/oa/login.do", http.StatusFound)
	})
	mux.HandleFunc("/oa/login.do", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><a href="/oa/portal.do">p</a><title>OA</title></html>`)
	})
	mux.HandleFunc("/oa/actuator/env", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"propertySources":[]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	lib := testLib(Rule{
		ID: "springboot-actuator", Name: "springboot-actuator", Paths: []string{"/actuator/env"},
		Matchers: []Matcher{{Type: MatcherWord, Value: []string{"propertySources"}}},
	})
	e := NewEngine(lib)
	c := mustClient(t)
	defer c.Close()

	res, err := e.Scan(context.Background(), c, Input{
		Origin:    srv.URL,
		BasePaths: []string{"/oa", "/"},
	}, Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("matches = %+v, want 1（/oa/actuator/env）", res.Matches)
	}
	m := res.Matches[0]
	if !strings.HasSuffix(m.URL, "/oa/actuator/env") {
		t.Errorf("URL = %q, want 以 /oa/actuator/env 结尾", m.URL)
	}
}

func TestEngineExtractsSubdirCandidatesFromHTML(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// /system 出现最多，应成为首选候选；static/js 等应被过滤。
		fmt.Fprint(w, `<html>
		<link href="/static/app.css"><script src="/js/main.js"></script>
		<a href="/system/user/list">u</a><a href="/system/role">r</a>
		<a href="/other/x">o</a>
		<script>var api="/system/api/v1";</script>
		</html>`)
	})
	mux.HandleFunc("/system/actuator/info", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"app":"demo","version":"1.0"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	lib := testLib(Rule{
		ID: "actuator-info", Name: "actuator-info", Paths: []string{"/actuator/info"},
		Matchers: []Matcher{{Type: MatcherWord, Value: []string{`"version"`}}},
	})
	e := NewEngine(lib)
	c := mustClient(t)
	defer c.Close()

	res, err := e.Scan(context.Background(), c, Input{Origin: srv.URL}, Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("matches = %+v, want 1（应通过 /system 子目录候选命中）", res.Matches)
	}
	if !strings.Contains(res.Matches[0].URL, "/system/actuator/info") {
		t.Errorf("URL = %q, want 含 /system/actuator/info", res.Matches[0].URL)
	}
}

func TestExtractSubdirsFiltersAndRanks(t *testing.T) {
	body := `<html>
	<link href="/static/a.css"><script src="/js/b.js"></script>
	<img src="/images/c.png"><a href="/oa/login.do">x</a>
	<a href="/oa/portal.do">y</a><a href="/oa/x.do">z</a>
	<a href="/admin/index">a</a>
	<script>const u="/oa/api/v1"</script>
	</html>`
	pages := []*httpx.Response{{Body: []byte(body), Header: http.Header{"Content-Type": []string{"text/html"}}}}
	got := ExtractSubdirs(pages, 2)
	if len(got) != 2 {
		t.Fatalf("got = %v, want 2 个", got)
	}
	if got[0] != "/oa" {
		t.Errorf("got[0] = %q, want /oa（出现频率最高）", got[0])
	}
	for _, g := range got {
		switch g {
		case "/static", "/js", "/images":
			t.Errorf("静态资源目录不应成为候选: %q", g)
		}
	}
}

func TestExtractSubdirsReturnsNilWhenNothing(t *testing.T) {
	pages := []*httpx.Response{{Body: []byte(`<html>no links</html>`)}}
	if got := ExtractSubdirs(pages, 5); got != nil {
		t.Errorf("got = %v, want nil", got)
	}
}

func TestFaviconMatchedViaLinkTag(t *testing.T) {
	icon := []byte("<svg>my-icon</svg>")
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><head><link rel="icon" href="/assets/logo.svg"></head></html>`)
	})
	mux.HandleFunc("/assets/logo.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Write(icon)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	lib := testLib(Rule{
		ID: "icon-rule", Name: "icon-rule", Paths: []string{"/"},
		Matchers: []Matcher{{Type: MatcherFavicon, Value: []string{MD5Hex(icon)}}},
	})
	e := NewEngine(lib)
	c := mustClient(t)
	defer c.Close()

	res, err := e.Scan(context.Background(), c, Input{Origin: srv.URL}, Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("matches = %+v, want 1（favicon 应通过 <link rel=icon> 命中）", res.Matches)
	}
	if res.Matches[0].Via != "favicon" {
		t.Errorf("Via = %q, want favicon", res.Matches[0].Via)
	}
}

func TestFaviconFallsBackToDefaultPath(t *testing.T) {
	icon := []byte("ICO-BYTES")
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html>no icon link</html>`)
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Write(icon)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	lib := testLib(Rule{
		ID: "icon-rule", Name: "icon-rule", Paths: []string{"/"},
		Matchers: []Matcher{{Type: MatcherFavicon, Value: []string{MD5Hex(icon)}}},
	})
	e := NewEngine(lib)
	c := mustClient(t)
	defer c.Close()

	res, _ := e.Scan(context.Background(), c, Input{Origin: srv.URL}, Options{})
	if len(res.Matches) != 1 {
		t.Fatalf("matches = %+v, want 1（回退 /favicon.ico）", res.Matches)
	}
}

func TestBaselineSoftNotFoundNotMatched(t *testing.T) {
	// 软 404：任何路径都返回同一页面且含 "welcome"。
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>welcome to our site</html>")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 规则关键字就是软 404 页面内容 → 会误报，属于预期内的规则质量问题；
	// 这里验证的是“探测到的是真实请求过的 URL”，交由 probe 层用基线过滤。
	lib := testLib(wordRule("noisy", "/admin/secret", "welcome"))
	e := NewEngine(lib)
	c := mustClient(t)
	defer c.Close()

	res, _ := e.Scan(context.Background(), c, Input{Origin: srv.URL}, Options{})
	if len(res.Matches) != 1 {
		t.Fatalf("matches = %+v, want 1", res.Matches)
	}
	if !strings.HasSuffix(res.Matches[0].URL, "/admin/secret") {
		t.Errorf("URL = %q, want 以 /admin/secret 结尾", res.Matches[0].URL)
	}
}

func TestEngineRespectsProbeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	var rules []Rule
	for i := 0; i < 30; i++ {
		rules = append(rules, wordRule(fmt.Sprintf("r%02d", i), fmt.Sprintf("/p%02d", i), "never"))
	}
	e := NewEngine(testLib(rules...))
	c := mustClient(t)
	defer c.Close()

	res, err := e.Scan(context.Background(), c, Input{Origin: srv.URL}, Options{MaxPathProbes: 5})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !res.Truncated {
		t.Error("Truncated = false, want true（应因上限停止）")
	}
	if res.Requests > 7 { // 1 根 + 5 探测 + 余量
		t.Errorf("Requests = %d, want <= 7", res.Requests)
	}
}

func TestEngineAndConditionRequiresAllMatchers(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>alpha only</html>")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	lib := testLib(Rule{
		ID: "and-rule", Name: "and-rule", Paths: []string{"/"},
		Matchers: []Matcher{{Type: MatcherWord, Cond: CondAnd, Value: []string{"alpha", "beta"}}},
	})
	e := NewEngine(lib)
	c := mustClient(t)
	defer c.Close()

	res, _ := e.Scan(context.Background(), c, Input{Origin: srv.URL}, Options{})
	if len(res.Matches) != 0 {
		t.Errorf("matches = %+v, want 空（and 需全部命中）", res.Matches)
	}
}

func TestEngineSkipsInvalidRegex(t *testing.T) {
	badRegex := Rule{
		ID: "bad-re", Name: "bad-re", Paths: []string{"/"},
		Matchers: []Matcher{
			{Type: MatcherRegex, Value: []string{"([unclosed"}},
		},
	}
	good := wordRule("good", "/", "hi")
	lib := testLib(badRegex, good)

	e := NewEngine(lib)
	if e.RegexSkipped != 1 {
		t.Errorf("RegexSkipped = %d, want 1", e.RegexSkipped)
	}
	if e.RuleCount() != 1 {
		t.Errorf("RuleCount = %d, want 1（无效正则的规则应被剔除）", e.RuleCount())
	}
}

func TestEngineDedupesMatchesByRuleID(t *testing.T) {
	// 同一规则的两个路径都命中时只报一次。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "shared-token")
	}))
	defer srv.Close()

	lib := testLib(Rule{
		ID: "dup", Name: "dup", Paths: []string{"/a", "/b"},
		Matchers: []Matcher{{Type: MatcherWord, Value: []string{"shared-token"}}},
	})
	e := NewEngine(lib)
	c := mustClient(t)
	defer c.Close()

	res, _ := e.Scan(context.Background(), c, Input{Origin: srv.URL}, Options{})
	if len(res.Matches) != 1 {
		t.Errorf("matches = %d, want 1（按规则 ID 去重）", len(res.Matches))
	}
}

func TestEngineManualBasePathWins(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/custom/actuator/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"UP"}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	lib := testLib(Rule{
		ID: "health", Name: "health", Paths: []string{"/actuator/health"},
		Matchers: []Matcher{{Type: MatcherWord, Value: []string{`"status"`}}},
	})
	e := NewEngine(lib)
	c := mustClient(t)
	defer c.Close()

	res, _ := e.Scan(context.Background(), c, Input{
		Origin:         srv.URL,
		ManualBasePath: "/custom",
	}, Options{})
	if len(res.Matches) != 1 {
		t.Fatalf("matches = %+v, want 1（--base-path 指定 /custom）", res.Matches)
	}
}

func TestResultsProductsDedupes(t *testing.T) {
	r1 := wordRule("a1", "/", "x")
	r1.Product = "nacos"
	r2 := wordRule("a2", "/", "y")
	r2.Product = "nacos"
	r3 := wordRule("a3", "/", "z")
	r3.Product = "redis"
	res := &Result{Matches: []Match{{Rule: &r1}, {Rule: &r2}, {Rule: &r3}}}
	got := res.Products()
	if len(got) != 2 || got[0] != "nacos" || got[1] != "redis" {
		t.Errorf("Products = %v, want [nacos redis]", got)
	}
}

func TestFindIconURLVariants(t *testing.T) {
	origin := "https://example.com"
	cases := []struct {
		html string
		want string
	}{
		{`<link rel="icon" href="/fav.png">`, "https://example.com/fav.png"},
		{`<link rel='shortcut icon' href='fav.ico'>`, "https://example.com/fav.ico"},
		{`<link href="/a.png" rel="apple-touch-icon">`, "https://example.com/a.png"},
		{`<link rel="stylesheet" href="/s.css">`, "https://example.com/favicon.ico"},
		{`<html>nothing</html>`, "https://example.com/favicon.ico"},
		{`<link rel="icon" href="//cdn.example.com/f.ico">`, "https://cdn.example.com/f.ico"},
		{`<link rel="icon" href="data:image/png;base64,AAA">`, "https://example.com/favicon.ico"},
	}
	for _, c := range cases {
		resp := &httpx.Response{URL: origin + "/", Body: []byte(c.html)}
		if got := FindIconURL(origin, resp); got != c.want {
			t.Errorf("FindIconURL(%q) = %q, want %q", c.html, got, c.want)
		}
	}
}

func mustClient(t *testing.T) *httpx.Client {
	t.Helper()
	c, err := httpx.New(httpx.Options{QPS: -1, Timeout: 3e9, MaxRequests: 200})
	if err != nil {
		t.Fatalf("httpx.New: %v", err)
	}
	return c
}
