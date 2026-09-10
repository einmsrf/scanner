package fingerprint

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// 真实指纹库的集成测试：依赖仓库根目录的 fingerprints.json（由 scanner update 生成）。
// 文件缺失时跳过，因此 CI 首次构建不会因此失败。
func loadRealLibrary(t *testing.T) *Library {
	t.Helper()
	data, err := os.ReadFile("../../fingerprints.json")
	if err != nil {
		t.Skipf("未找到 fingerprints.json，跳过真实指纹库测试: %v", err)
	}
	lib, err := ParseLibrary(data)
	if err != nil {
		t.Fatalf("ParseLibrary: %v", err)
	}
	return lib
}

func TestRealLibraryScaleAndComposition(t *testing.T) {
	lib := loadRealLibrary(t)
	if lib.Count < 3000 {
		t.Errorf("规则数 = %d, want >= 3000（上游约 3.3k）", lib.Count)
	}
	if lib.Source == "" || lib.GeneratedAt == "" {
		t.Errorf("缺少来源信息: source=%q generated_at=%q", lib.Source, lib.GeneratedAt)
	}

	var word, regex, favicon int
	for _, r := range lib.Rules {
		for _, m := range r.Matchers {
			switch m.Type {
			case MatcherWord:
				word++
			case MatcherRegex:
				regex++
			case MatcherFavicon:
				favicon++
			default:
				t.Errorf("规则 %s 含未知 matcher 类型 %q", r.ID, m.Type)
			}
		}
		if len(r.Paths) == 0 {
			t.Errorf("规则 %s 缺少 paths", r.ID)
		}
	}
	// 与上游原始统计对齐（word 3032 / regex 476 / favicon 281，其中 1 个 regex 属 extractors）
	if word != 3032 {
		t.Errorf("word matcher = %d, want 3032", word)
	}
	if regex != 475 {
		t.Errorf("regex matcher = %d, want 475", regex)
	}
	if favicon != 281 {
		t.Errorf("favicon matcher = %d, want 281", favicon)
	}
}

func TestRealLibraryEngineIndexing(t *testing.T) {
	lib := loadRealLibrary(t)
	e := NewEngine(lib)
	if e.RegexSkipped != 0 {
		t.Errorf("RegexSkipped = %d, want 0（上游正则应全部可编译）", e.RegexSkipped)
	}
	if e.RuleCount() != lib.Count {
		t.Errorf("RuleCount = %d, want %d（不应有规则被剔除）", e.RuleCount(), lib.Count)
	}

	// 含 favicon matcher 的“规则数”少于 favicon matcher 总数（有 1 条含 2 个）。
	wantIconRules := 0
	for _, r := range lib.Rules {
		for _, m := range r.Matchers {
			if m.Type == MatcherFavicon {
				wantIconRules++
				break
			}
		}
	}
	if len(e.iconIdx) != wantIconRules {
		t.Errorf("favicon 规则索引 = %d, want %d", len(e.iconIdx), wantIconRules)
	}
	// 上游指纹库以根路径为主，非根路径极少（设计第 3 层的必要性就体现在这里）。
	if e.PathCount() == 0 {
		t.Error("PathCount = 0，路径索引未建立")
	}
	if len(e.rootIdx) < 3000 {
		t.Errorf("rootIdx = %d, want >= 3000（绝大多数规则是根路径型）", len(e.rootIdx))
	}
	t.Logf("指纹库: %d 条规则（根路径型 %d、favicon %d）、%d 个非根探测路径",
		e.RuleCount(), len(e.rootIdx), len(e.iconIdx), e.PathCount())
}

// 端到端：模拟一个 nacos 站点，验证四层兜底里第 1、2 层能命中真实规则。
func TestRealLibraryMatchesNacosSite(t *testing.T) {
	lib := loadRealLibrary(t)
	e := NewEngine(lib)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			// 真实场景常见：根路径 302 到应用入口
			http.Redirect(w, r, "/nacos/", http.StatusFound)
			return
		}
		if r.URL.Path == "/nacos/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><title>nacos</title></head><body>Nacos console</body></html>`)
			return
		}
		w.WriteHeader(404)
		fmt.Fprint(w, "not found")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := mustClient(t)
	defer c.Close()

	res, err := e.Scan(context.Background(), c, Input{
		Origin:    srv.URL,
		BasePaths: []string{"/nacos", "/"},
	}, Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var found []string
	for _, m := range res.Matches {
		found = append(found, m.Rule.ID)
	}
	if !containsID(found, "alibaba-nacos") {
		t.Errorf("未命中 alibaba-nacos；命中列表 = %v", found)
	}
	t.Logf("命中 %d 条指纹: %v", len(found), found)
}

// 第 3 层兜底：应用入口在子目录 /app/ 下（根路径只是一个门户页），
// 引擎应从首页的一级目录候选里发现 /app 并把根路径型规则套上去。
func TestRealLibrarySubdirBaseDetection(t *testing.T) {
	lib := loadRealLibrary(t)
	e := NewEngine(lib)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			// 门户页：只暴露到 /app 的链接，本身不含任何指纹特征。
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body>
				<a href="/app/console">控制台</a>
				<a href="/app/help">帮助</a>
				<script src="/app/static/main.js"></script>
			</body></html>`)
		case "/app/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><title>nacos</title></head><body>Nacos console</body></html>`)
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, "not found")
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := mustClient(t)
	defer c.Close()

	res, err := e.Scan(context.Background(), c, Input{Origin: srv.URL}, Options{MaxSubdirs: 5})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var nacos *Match
	for i := range res.Matches {
		if res.Matches[i].Rule.ID == "alibaba-nacos" {
			nacos = &res.Matches[i]
		}
	}
	if nacos == nil {
		var got []string
		for _, m := range res.Matches {
			got = append(got, m.Rule.ID+"@"+m.URL)
		}
		t.Fatalf("未通过子目录候选 /app 命中 nacos；命中 = %v", got)
	}
	if nacos.Via != "subdir" {
		t.Errorf("Via = %q, want subdir（应通过候选 base 命中）", nacos.Via)
	}
	if !strings.HasSuffix(nacos.URL, "/app/") {
		t.Errorf("URL = %q, want 以 /app/ 结尾", nacos.URL)
	}
}

// 非根路径规则：etcd 的 /version 需要同时含 etcdcluster 与 etcdserver（condition: and）。
func TestRealLibraryNonRootPathRule(t *testing.T) {
	lib := loadRealLibrary(t)
	e := NewEngine(lib)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"etcdserver":"3.5.0","etcdcluster":"3.5.0"}`)
			return
		}
		w.WriteHeader(404)
		fmt.Fprint(w, `<html>portal</html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := mustClient(t)
	defer c.Close()

	res, err := e.Scan(context.Background(), c, Input{Origin: srv.URL}, Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var hit bool
	for _, m := range res.Matches {
		if m.Rule.ID == "etcd-io" {
			hit = true
			if m.Via != "path" {
				t.Errorf("Via = %q, want path", m.Via)
			}
			if !strings.HasSuffix(m.URL, "/version") {
				t.Errorf("URL = %q, want 以 /version 结尾", m.URL)
			}
		}
	}
	if !hit {
		t.Error("未命中 etcd-io（/version 的非根路径规则）")
	}
}

// and 条件只命中一半时必须不报（避免误报）。
func TestRealLibraryAndConditionNotPartial(t *testing.T) {
	lib := loadRealLibrary(t)
	e := NewEngine(lib)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			// 只有 etcdserver，缺 etcdcluster → and 不成立
			fmt.Fprint(w, `{"etcdserver":"3.5.0"}`)
			return
		}
		w.WriteHeader(404)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := mustClient(t)
	defer c.Close()

	res, _ := e.Scan(context.Background(), c, Input{Origin: srv.URL}, Options{})
	for _, m := range res.Matches {
		if m.Rule.ID == "etcd-io" {
			t.Error("etcd-io 误报：condition=and 只命中一半不应成立")
		}
	}
}

func containsID(list []string, id string) bool {
	for _, s := range list {
		if s == id {
			return true
		}
	}
	return false
}
