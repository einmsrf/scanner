package probe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/einmsrf/scanner/pkg/fingerprint"
	"github.com/einmsrf/scanner/pkg/httpx"
)

func mustLib(t *testing.T, packs, exposure string) *Library {
	t.Helper()
	lib, err := Load([]byte(packs), []byte(exposure))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return lib
}

func mustClient(t *testing.T) *httpx.Client {
	t.Helper()
	c, err := httpx.New(httpx.Options{QPS: -1, Timeout: 3e9, MaxRequests: 300})
	if err != nil {
		t.Fatalf("httpx.New: %v", err)
	}
	return c
}

func ruleWith(id, product string, tags ...string) fingerprint.Rule {
	return fingerprint.Rule{ID: id, Name: id, Product: product, Tags: tags, Paths: []string{"/"}}
}

func matchOf(r fingerprint.Rule) fingerprint.Match { return fingerprint.Match{Rule: &r} }

const testPacks = `
__always__:
- path: /actuator/env
  matcher: propertySources
  name: Spring Actuator 环境变量
  severity: high
spring:
- path: /actuator/mappings
  matcher: mappings
  name: Actuator 映射
  severity: medium
jenkins:
- path: /api/json
  matcher: _class
  name: Jenkins API
  severity: high
`

const testExposure = `
- path: /.git/HEAD
  matcher: "ref: refs/"
  name: Git 暴露
  severity: high
- path: /.env
  matcher: "^[A-Za-z_][A-Za-z0-9_]*="
  regex: true
  name: .env 暴露
  severity: critical
`

func TestParseRequiresMatcher(t *testing.T) {
	bad := `
spring:
- path: /actuator/env
  name: 没有 matcher
`
	_, err := ParseProbePacks([]byte(bad))
	if err == nil {
		t.Fatal("err = nil, want 缺少 matcher 必须报错（裸 200 不算命中）")
	}
	if !strings.Contains(err.Error(), "matcher") {
		t.Errorf("错误信息应提到 matcher: %v", err)
	}
}

func TestParseRejectsBadRegex(t *testing.T) {
	bad := `
spring:
- path: /x
  matcher: "([unclosed"
  regex: true
`
	if _, err := ParseProbePacks([]byte(bad)); err == nil {
		t.Fatal("err = nil, want 正则无效报错")
	}
}

func TestParseNormalizesPathAndSeverity(t *testing.T) {
	lib := mustLib(t, `
spring:
- path: actuator/env
  matcher: x
`, testExposure)
	specs := lib.Pack("spring")
	if len(specs) != 1 {
		t.Fatalf("specs = %d", len(specs))
	}
	if specs[0].Path != "/actuator/env" {
		t.Errorf("Path = %q, want /actuator/env（自动补前导斜杠）", specs[0].Path)
	}
	if specs[0].SeverityOrInfo() != "info" {
		t.Errorf("SeverityOrInfo = %q, want info（未标注时回退）", specs[0].SeverityOrInfo())
	}
	if specs[0].Title() != "/actuator/env" {
		t.Errorf("Title = %q, want 回退到路径", specs[0].Title())
	}
}

func TestSelectFamilies(t *testing.T) {
	lib := mustLib(t, testPacks, testExposure)

	cases := []struct {
		name    string
		matches []fingerprint.Match
		want    []string
	}{
		{"无指纹不选", nil, nil},
		{
			"spring-boot-admin 命中 spring 族",
			[]fingerprint.Match{matchOf(ruleWith("spring-boot-admin", "spring-boot-admin"))},
			[]string{"spring"},
		},
		{
			"由 tags 命中",
			[]fingerprint.Match{matchOf(ruleWith("x", "x", "Jenkins"))},
			[]string{"jenkins"},
		},
		{
			"由 id 下单划线变体命中",
			[]fingerprint.Match{matchOf(ruleWith("jenkins_console", ""))},
			[]string{"jenkins"},
		},
		{
			"无关指纹不误选",
			[]fingerprint.Match{matchOf(ruleWith("nginx", "nginx"))},
			nil,
		},
	}
	for _, c := range cases {
		got := lib.SelectFamilies(c.matches)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			}
		}
	}
}

func TestRunFindsAlwaysProbeWithoutFingerprint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/actuator/env" {
			fmt.Fprint(w, `{"propertySources":[{"name":"x"}]}`)
			return
		}
		w.WriteHeader(404)
		fmt.Fprint(w, "nope")
	}))
	defer srv.Close()

	lib := mustLib(t, testPacks, testExposure)
	p := New(lib)
	c := mustClient(t)
	defer c.Close()

	rep := p.Run(context.Background(), c, srv.URL, nil, nil, Options{})
	if len(rep.Findings) != 1 {
		t.Fatalf("findings = %+v, want 1（__always__ 族无需指纹）", rep.Findings)
	}
	f := rep.Findings[0]
	if f.Spec.Path != "/actuator/env" || f.Family != AlwaysFamily {
		t.Errorf("finding = %+v", f)
	}
	if !strings.Contains(f.Evidence, "propertySources") {
		t.Errorf("Evidence = %q, want 含 propertySources", f.Evidence)
	}
}

func TestRunFamilyProbeOnlyWithFingerprint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/actuator/mappings" {
			fmt.Fprint(w, `{"contexts":{"x":{"mappings":[]}}}`)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	lib := mustLib(t, testPacks, testExposure)
	p := New(lib)
	c := mustClient(t)
	defer c.Close()

	// 无指纹 → 不应探测 spring 族的 /actuator/mappings
	rep := p.Run(context.Background(), c, srv.URL, nil, nil, Options{SkipAlways: true, SkipGeneric: true})
	if len(rep.Findings) != 0 {
		t.Errorf("findings = %+v, want 空（无指纹不跑族探测）", rep.Findings)
	}
	for _, u := range rep.Probed {
		if strings.Contains(u, "/actuator/mappings") {
			t.Error("未命中指纹却探测了族专属路径")
		}
	}

	// 有指纹 → 应探测并命中
	m := matchOf(ruleWith("spring-boot-admin", "spring-boot-admin"))
	rep = p.Run(context.Background(), c, srv.URL, []fingerprint.Match{m}, nil, Options{SkipAlways: true, SkipGeneric: true})
	if len(rep.Findings) != 1 {
		t.Fatalf("findings = %+v, want 1", rep.Findings)
	}
	if rep.Findings[0].Family != "spring" {
		t.Errorf("Family = %q, want spring", rep.Findings[0].Family)
	}
}

func TestRunGenericExposureMatchers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.git/HEAD":
			fmt.Fprint(w, "ref: refs/heads/main\n")
		case "/.env":
			fmt.Fprint(w, "APP_KEY=abc\nDB_PASS=xyz\n")
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, "not found")
		}
	}))
	defer srv.Close()

	lib := mustLib(t, testPacks, testExposure)
	p := New(lib)
	c := mustClient(t)
	defer c.Close()

	rep := p.Run(context.Background(), c, srv.URL, nil, nil, Options{SkipAlways: true})
	if len(rep.Findings) != 2 {
		t.Fatalf("findings = %+v, want 2（.git/HEAD 与 .env）", rep.Findings)
	}
	var gotGit, gotEnv bool
	for _, f := range rep.Findings {
		switch f.Spec.Path {
		case "/.git/HEAD":
			gotGit = true
		case "/.env":
			gotEnv = true
		}
	}
	if !gotGit || !gotEnv {
		t.Errorf("缺少命中: git=%v env=%v", gotGit, gotEnv)
	}
}

func TestRunBare200WithoutMatcherIsNotAHit(t *testing.T) {
	// 所有路径都返回 200 但不含任何特征串 → 一条都不该命中。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "<html>welcome</html>")
	}))
	defer srv.Close()

	lib := mustLib(t, testPacks, testExposure)
	p := New(lib)
	c := mustClient(t)
	defer c.Close()

	rep := p.Run(context.Background(), c, srv.URL, nil, nil, Options{})
	if len(rep.Findings) != 0 {
		t.Errorf("findings = %+v, want 空（裸 200 不算命中）", rep.Findings)
	}
}

func TestRunBaselineFiltersSoftNotFound(t *testing.T) {
	// 软 404：任何不存在的路径都返回与基线一致的页面，且该页面恰好含 matcher 字面量。
	body := `<html>propertySources ref: refs/ APP_KEY=1</html>`
	mux := http.NewServeMux()
	mux.HandleFunc("/real", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ref: refs/heads/main")
	})
	srv := httptest.NewServer(mux)
	// 默认处理器：任何其它路径都返回软 404 页面（含 matcher 字面量）
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/real" {
			fmt.Fprint(w, "ref: refs/heads/main")
			return
		}
		fmt.Fprint(w, body)
	})
	defer srv.Close()

	lib := mustLib(t, testPacks, testExposure)
	p := New(lib)
	c := mustClient(t)
	defer c.Close()

	// 先取基线（会命中软 404 页面）
	bl, err := c.FetchBaselineAt(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchBaselineAt: %v", err)
	}
	if !bl.Wildcard {
		t.Fatalf("Baseline.Wildcard = false, want true (%s)", bl)
	}

	rep := p.Run(context.Background(), c, srv.URL, nil, bl, Options{})
	if len(rep.Findings) != 0 {
		t.Errorf("findings = %+v, want 空（软 404 必须被基线过滤）", rep.Findings)
	}
}

func TestRunRespectsRequestLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	lib := mustLib(t, testPacks, testExposure)
	p := New(lib)
	c := mustClient(t)
	defer c.Close()

	// 队列共 3 条（1 条 __always__ + 2 条通用），上限 2 应触发截断。
	rep := p.Run(context.Background(), c, srv.URL, nil, nil, Options{MaxRequests: 2})
	if !rep.Truncated {
		t.Errorf("Truncated = false, want true（队列 %d 条 > 上限 2）", 3)
	}
	if rep.Requests > 2 {
		t.Errorf("Requests = %d, want <= 2", rep.Requests)
	}
}

func TestRunBaseFallbackFindsSubdirDeployment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oa/actuator/env" {
			fmt.Fprint(w, `{"propertySources":[]}`)
			return
		}
		w.WriteHeader(404)
		fmt.Fprint(w, "not found")
	}))
	defer srv.Close()

	lib := mustLib(t, testPacks, testExposure)
	p := New(lib)
	c := mustClient(t)
	defer c.Close()

	rep := p.Run(context.Background(), c, srv.URL, nil, nil, Options{
		Bases: []string{"", "/oa"},
	})
	if len(rep.Findings) != 1 {
		t.Fatalf("findings = %+v, want 1（应回退到 /oa base）", rep.Findings)
	}
	if !strings.HasSuffix(rep.Findings[0].URL, "/oa/actuator/env") {
		t.Errorf("URL = %q, want 以 /oa/actuator/env 结尾", rep.Findings[0].URL)
	}
}

func TestRunSoftNotFoundLimitsBases(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>soft 404</html>")
	}))
	defer srv.Close()

	lib := mustLib(t, testPacks, testExposure)
	p := New(lib)
	c := mustClient(t)
	defer c.Close()

	bl, _ := c.FetchBaselineAt(context.Background(), srv.URL)
	rep := p.Run(context.Background(), c, srv.URL, nil, bl, Options{
		Bases: []string{"", "/a", "/b", "/c"},
	})
	// 通配站点下每个探测项只应尝试 MaxBasesPerSpec 个 base
	if rep.Requests > 3*DefaultMaxBasesPerSpec+2 {
		t.Errorf("Requests = %d, 通配站点下未限制 base 尝试次数", rep.Requests)
	}
	var hasNote bool
	for _, n := range rep.Notes {
		if strings.Contains(n, "软 404") {
			hasNote = true
		}
	}
	if !hasNote {
		t.Errorf("应在 Notes 里说明限制了 base: %v", rep.Notes)
	}
}

func TestEvaluateHeaderPart(t *testing.T) {
	resp := &httpx.Response{
		Header: http.Header{"Server": []string{"Apache-Coyote/1.1"}},
		Body:   []byte("nothing here"),
	}
	s := Spec{Path: "/x", Matcher: "Coyote", Part: "header"}
	if hit, _ := s.evaluate(resp); !hit {
		t.Error("header 匹配应命中")
	}
	s2 := Spec{Path: "/x", Matcher: "coyote", Part: "body"}
	if hit, _ := s2.evaluate(resp); hit {
		t.Error("body 匹配不应命中（内容在响应头里）")
	}
}

func TestEvaluateCaseInsensitiveSubstring(t *testing.T) {
	resp := &httpx.Response{Body: []byte("<TITLE>Nacos</TITLE>")}
	s := Spec{Path: "/", Matcher: "<title>nacos</title>"}
	if hit, _ := s.evaluate(resp); !hit {
		t.Error("子串匹配应大小写不敏感")
	}
}

func TestEvaluateRegex(t *testing.T) {
	resp := &httpx.Response{Body: []byte("APP_KEY=1\n# comment\nDB=2\n")}
	s := Spec{Path: "/.env", Matcher: `^[A-Za-z_][A-Za-z0-9_]*=`, Regex: true}
	if err := s.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if hit, _ := s.evaluate(resp); !hit {
		t.Error("正则匹配应命中")
	}
}

func TestJoinBase(t *testing.T) {
	cases := []struct{ base, p, want string }{
		{"", "/.env", "/.env"},
		{"/", "/.env", "/.env"},
		{"/oa", "/actuator/env", "/oa/actuator/env"},
		{"/oa/", "/actuator/env", "/oa/actuator/env"},
		{"oa", "/x", "/oa/x"},
	}
	for _, c := range cases {
		if got := joinBase(c.base, c.p); got != c.want {
			t.Errorf("joinBase(%q,%q) = %q, want %q", c.base, c.p, got, c.want)
		}
	}
}
