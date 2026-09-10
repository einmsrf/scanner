package target

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/einmsrf/scanner/pkg/httpx"
)

func TestParseForms(t *testing.T) {
	cases := []struct {
		in       string
		host     string
		port     int
		scheme   string
		basePath string
	}{
		{"example.com", "example.com", 0, "", ""},
		{"1.2.3.4", "1.2.3.4", 0, "", ""},
		{"1.2.3.4:8080", "1.2.3.4", 8080, "", ""},
		{"example.com:8443", "example.com", 8443, "", ""},
		{"https://example.com/app", "example.com", 0, "https", "/app"},
		{"http://1.2.3.4:9000/oa/login.do", "1.2.3.4", 9000, "http", "/oa/login.do"},
		{"example.com/admin/", "example.com", 0, "", "/admin"},
		{"  example.com  ", "example.com", 0, "", ""},
		{"example.com?a=b", "example.com", 0, "", ""},
		{"https://example.com/a/b?x=1#f", "example.com", 0, "https", "/a/b"},
		{"[::1]:8080", "::1", 8080, "", ""},
		{"HTTPS://Example.COM", "Example.COM", 0, "https", ""},
		{"user:pass@example.com:8080", "example.com", 8080, "", ""},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if err != nil {
			t.Errorf("Parse(%q) error: %v", c.in, err)
			continue
		}
		if got.Host != c.host || got.Port != c.port || got.Scheme != c.scheme || got.BasePath != c.basePath {
			t.Errorf("Parse(%q) = host=%q port=%d scheme=%q base=%q; want host=%q port=%d scheme=%q base=%q",
				c.in, got.Host, got.Port, got.Scheme, got.BasePath, c.host, c.port, c.scheme, c.basePath)
		}
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	for _, in := range []string{"ftp://example.com", "example.com:99999", "example.com:abc", ":8080", "[]"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) err = nil, want error", in)
		}
	}
}

func TestParseEmptyAndComments(t *testing.T) {
	for _, in := range []string{"", "   ", "# comment", "#example.com", "\t"} {
		if _, err := Parse(in); err != ErrEmpty {
			t.Errorf("Parse(%q) err = %v, want ErrEmpty", in, err)
		}
	}
}

func TestURLFor(t *testing.T) {
	cases := []struct {
		in     string
		scheme string
		want   string
	}{
		{"example.com", "https", "https://example.com"},
		{"example.com", "http", "http://example.com"},
		{"example.com:8443", "https", "https://example.com:8443"},
		{"example.com:8443", "http", "http://example.com:8443"},
		{"example.com:443", "https", "https://example.com"},
		{"example.com:80", "http", "http://example.com"},
		{"1.2.3.4:8080", "https", "https://1.2.3.4:8080"},
		{"example.com/app", "https", "https://example.com/app"},
		{"[::1]:8080", "http", "http://[::1]:8080"},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.in, err)
		}
		if u := got.URLFor(c.scheme); u != c.want {
			t.Errorf("URLFor(%q, %s) = %q, want %q", c.in, c.scheme, u, c.want)
		}
	}
}

func TestPreferredSchemes(t *testing.T) {
	bare, _ := Parse("example.com")
	if got := bare.PreferredSchemes(false); !reflect.DeepEqual(got, []string{"https", "http"}) {
		t.Errorf("bare/false = %v", got)
	}
	if got := bare.PreferredSchemes(true); !reflect.DeepEqual(got, []string{"https", "http"}) {
		t.Errorf("bare/true = %v", got)
	}
	explicit, _ := Parse("http://example.com")
	if got := explicit.PreferredSchemes(false); !reflect.DeepEqual(got, []string{"http"}) {
		t.Errorf("explicit/false = %v", got)
	}
	if got := explicit.PreferredSchemes(true); !reflect.DeepEqual(got, []string{"http", "https"}) {
		t.Errorf("explicit/true = %v", got)
	}
}

func TestIsIP(t *testing.T) {
	ip, _ := Parse("1.2.3.4:8080")
	if !ip.IsIP() {
		t.Error("1.2.3.4 应判定为 IP")
	}
	host, _ := Parse("example.com")
	if host.IsIP() {
		t.Error("example.com 不应判定为 IP")
	}
}

func TestParseAllDedupesAndSkips(t *testing.T) {
	in := `
# 目标列表
example.com
example.com
1.2.3.4:8080

# 注释
https://example.com
bad::input
`
	targets, bad, err := ParseAll(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseAll: %v", err)
	}
	// example.com（bare）与 https://example.com（显式 https）Key 不同，各算一个。
	if len(targets) != 3 {
		t.Errorf("targets = %d (%v), want 3", len(targets), targets)
	}
	if len(bad) != 1 {
		t.Errorf("bad = %v, want 1 条", bad)
	}
}

func TestProbeFallsBackToHTTP(t *testing.T) {
	// 只有 http 可用（Go 的 httptest 默认明文服务）。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	tg, err := Parse(srv.URL) // http://127.0.0.1:port
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// 去掉显式 scheme，模拟用户只给 host:port，让探测自行降级。
	tg.Scheme = ""

	c := mustClient(t)
	defer c.Close()

	sites, err := Probe(context.Background(), c, tg, false)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(sites) != 1 {
		t.Fatalf("sites = %d, want 1", len(sites))
	}
	if sites[0].Scheme != "http" {
		t.Errorf("scheme = %q, want http（https 应失败后降级）", sites[0].Scheme)
	}
	if sites[0].Landing.Status != 200 {
		t.Errorf("landing status = %d, want 200", sites[0].Landing.Status)
	}
}

func TestProbeBothReturnsBothSchemes(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "secure")
	}))
	defer srv.Close()

	// 同一个端口上只跑 TLS：https 成功，http 失败 → 只返回 https。
	tg, err := Parse(srv.URL)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	tg.Scheme = ""

	c := mustClient(t)
	defer c.Close()

	sites, err := Probe(context.Background(), c, tg, true)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(sites) != 1 || sites[0].Scheme != "https" {
		t.Fatalf("sites = %v, want 仅 https 一个", sites)
	}
}

func TestProbeFollowsRedirectAndCandidateBases(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/oa/login.do", http.StatusFound)
			return
		}
		fmt.Fprint(w, "not found")
	})
	mux.HandleFunc("/oa/login.do", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<title>OA</title>")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tg, err := Parse(srv.URL)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	c := mustClient(t)
	defer c.Close()

	sites, err := Probe(context.Background(), c, tg, false)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	s := sites[0]
	if s.LandingPath != "/oa/login.do" {
		t.Errorf("LandingPath = %q, want /oa/login.do", s.LandingPath)
	}
	// 第 1 层兜底：落地页目录 /oa 应排在候选 base 首位。
	got := s.CandidateBases()
	want := []string{"/oa", "/"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CandidateBases = %v, want %v", got, want)
	}
}

func TestProbeFetchesRootWhenBasePath404s(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			fmt.Fprint(w, "<title>Root App</title>")
			return
		}
		w.WriteHeader(404)
		fmt.Fprint(w, "nope")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tg, err := Parse(srv.URL + "/wrong/path")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	c := mustClient(t)
	defer c.Close()

	sites, err := Probe(context.Background(), c, tg, false)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	s := sites[0]
	if s.Landing.Status != 404 {
		t.Errorf("landing status = %d, want 404", s.Landing.Status)
	}
	if s.RootLanding == nil {
		t.Fatal("RootLanding = nil, want 补取的根路径响应")
	}
	if len(s.Responses()) != 2 {
		t.Errorf("Responses = %d, want 2（主 + 根兜底）", len(s.Responses()))
	}
}

func TestProbeAllSchemesFail(t *testing.T) {
	// 未监听的端口，确保两个协议都连不上。
	tg, err := Parse("127.0.0.1:1")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	c := mustClient(t)
	defer c.Close()

	if _, err := Probe(context.Background(), c, tg, false); err == nil {
		t.Fatal("err = nil, want 全部协议失败")
	}
}

func mustClient(t *testing.T) *httpx.Client {
	t.Helper()
	c, err := httpx.New(httpx.Options{QPS: -1, Timeout: 3e9})
	if err != nil {
		t.Fatalf("httpx.New: %v", err)
	}
	return c
}
