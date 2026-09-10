package httpx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGetFollowsRedirectsAndReportsFinalURL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/oa/login.do", http.StatusFound)
	})
	mux.HandleFunc("/oa/login.do", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<title>OA Login</title>")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := mustClient(t, Options{QPS: -1})
	defer c.Close()

	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status = %d, want 200", resp.Status)
	}
	if !strings.HasSuffix(resp.URL, "/oa/login.do") {
		t.Errorf("final URL = %q, want suffix /oa/login.do", resp.URL)
	}
	if len(resp.Redirects) != 1 {
		t.Errorf("redirects = %v, want 1 hop", resp.Redirects)
	}
	if !strings.Contains(resp.Text(), "OA Login") {
		t.Errorf("body = %q, want OA Login", resp.Text())
	}
	if !resp.IsHTML() {
		t.Errorf("ContentType = %q, want html", resp.ContentType())
	}
}

func TestTLSVerifySkippedByDefault(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	c := mustClient(t, Options{QPS: -1})
	defer c.Close()

	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("自签证书默认应被跳过校验，却失败: %v", err)
	}
	if resp.Text() != "ok" {
		t.Errorf("body = %q, want ok", resp.Text())
	}
}

func TestBodyIsTruncatedAtLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("A", 5000))
	}))
	defer srv.Close()

	c := mustClient(t, Options{QPS: -1})
	defer c.Close()

	resp, err := c.Do(context.Background(), &Request{URL: srv.URL, MaxBody: 100})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(resp.Body) != 100 {
		t.Errorf("len(Body) = %d, want 100", len(resp.Body))
	}
	if !resp.Truncated {
		t.Error("Truncated = false, want true")
	}
}

func TestBudgetExhaustion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	c := mustClient(t, Options{QPS: -1, MaxRequests: 2})
	defer c.Close()

	for i := 0; i < 2; i++ {
		if _, err := c.Get(context.Background(), srv.URL); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if _, err := c.Get(context.Background(), srv.URL); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("err = %v, want ErrBudgetExceeded", err)
	}
	if c.Used() != 2 || c.Remaining() != 0 {
		t.Errorf("used=%d remaining=%d, want 2/0", c.Used(), c.Remaining())
	}
}

func TestBaselineDetectsWildcard200(t *testing.T) {
	// 软 404：任何路径都返回 200 且内容一致。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>Not Found Page</body></html>")
	}))
	defer srv.Close()

	c := mustClient(t, Options{QPS: -1})
	defer c.Close()

	bl, err := c.FetchBaselineAt(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchBaselineAt: %v", err)
	}
	if !bl.Wildcard {
		t.Errorf("Wildcard = false, want true (%s)", bl)
	}

	// 同形响应必须被判为“等价于基线” → 过滤掉。
	probe, err := c.Get(context.Background(), srv.URL+"/.env")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !bl.SameAs(probe) {
		t.Errorf("SameAs = false, want true（软 404 应被过滤）")
	}
}

func TestBaselineAllowsGenuineHit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "APP_KEY=secretvalue123\nDB_PASSWORD=hunter2\n")
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "User-agent: *\nDisallow: /admin\n")
		default:
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(404)
			fmt.Fprint(w, "<html><title>404 Not Found</title></html>")
		}
	}))
	defer srv.Close()

	c := mustClient(t, Options{QPS: -1})
	defer c.Close()

	bl, err := c.FetchBaselineAt(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchBaselineAt: %v", err)
	}
	if bl.Wildcard {
		t.Errorf("Wildcard = true, want false (%s)", bl)
	}
	if bl.Status != 404 {
		t.Errorf("baseline status = %d, want 404", bl.Status)
	}

	hit, err := c.Get(context.Background(), srv.URL+"/.env")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if bl.SameAs(hit) {
		t.Error("SameAs = true, want false（真实命中不应被过滤）")
	}
}

func TestBaselineToleratesDynamicWildcardBody(t *testing.T) {
	// 通配 200，但每次响应长度略有不同（模拟随机 token）。
	var n int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		pad := strings.Repeat("x", n)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>not found "+pad+"</body></html>")
	}))
	defer srv.Close()

	c := mustClient(t, Options{QPS: -1})
	defer c.Close()

	bl, err := c.FetchBaselineAt(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchBaselineAt: %v", err)
	}
	if !bl.Wildcard {
		t.Fatalf("Wildcard = false, want true (%s)", bl)
	}
	probe, err := c.Get(context.Background(), srv.URL+"/admin")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !bl.SameAs(probe) {
		t.Errorf("SameAs = false, want true（长度容差内应判为同一页面）")
	}
}

func TestRateLimitSpacesRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	// QPS=5 → 间隔 200ms；3 次请求总耗时至少 400ms。
	c := mustClient(t, Options{QPS: 5})
	defer c.Close()

	start := time.Now()
	for i := 0; i < 3; i++ {
		if _, err := c.Get(context.Background(), srv.URL); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if elapsed := time.Since(start); elapsed < 350*time.Millisecond {
		t.Errorf("elapsed = %v, want >= 350ms（限速未生效）", elapsed)
	}
}

func TestConcurrentGetsAreSafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	c := mustClient(t, Options{QPS: -1, MaxRequests: 50})
	defer c.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Get(context.Background(), srv.URL); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("并发请求失败: %v", err)
	}
	if c.Used() != 50 {
		t.Errorf("Used = %d, want 50", c.Used())
	}
}

func TestInvalidProxyIsRejected(t *testing.T) {
	_, err := New(Options{Proxy: "://bad"})
	if err == nil {
		t.Fatal("err = nil, want 代理地址无效")
	}
}

func TestContextCancelAbortsWait(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	c := mustClient(t, Options{QPS: 1}) // 间隔 1s
	defer c.Close()

	if _, err := c.Get(context.Background(), srv.URL); err != nil {
		t.Fatalf("预热请求: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Get(ctx, srv.URL); err == nil {
		t.Fatal("err = nil, want context deadline exceeded")
	}
}

func mustClient(t *testing.T, o Options) *Client {
	t.Helper()
	c, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}
