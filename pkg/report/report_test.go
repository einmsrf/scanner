package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/einmsrf/scanner/pkg/fingerprint"
	"github.com/einmsrf/scanner/pkg/jsaudit"
	"github.com/einmsrf/scanner/pkg/probe"
)

func sampleTarget() *TargetReport {
	return &TargetReport{
		Target:   "https://example.com",
		URL:      "https://example.com/oa/login.do",
		Scheme:   "https",
		Status:   200,
		Title:    "OA 系统",
		Server:   "nginx",
		Duration: "1.2s",
		Requests: 23,
		Fingerprints: []FingerprintHit{
			{ID: "alibaba-nacos", Product: "nacos", Vendor: "alibaba", Path: "/", Via: "landing", Evidence: "word:<title>nacos</title>"},
		},
		Exposures: []Exposure{
			{Family: "spring", Name: "Spring Boot Actuator 环境变量", Severity: "high", Path: "/actuator/env", Evidence: "matcher:propertySources"},
			{Family: "generic", Name: "Git 仓库目录暴露", Severity: "critical", Path: "/.git/HEAD", Evidence: "matcher:ref: refs/"},
		},
		JS: &JSSection{
			AssetsScanned: 3,
			SourceMapHits: 1,
			Findings: []JSFinding{
				{
					Category: "硬编码凭证", CategoryKey: "hardcoded-credential", Severity: "high",
					File: "https://example.com/app.js", Line: 12, Source: "external",
					Value: "YWRtaW46YWJjZEAxMjM0", Decoded: "admin:abcd@1234",
					Evidence: "Authorization:\"Basic YWRtaW46YWJjZEAxMjM0\"", Entropy: 3.64,
					Semantic: &SemanticNote{Judged: true, IsSensitive: true, Reason: "真实 Basic 凭证", Confidence: 0.97},
				},
				{
					Category: "内网信息", CategoryKey: "internal-info", Severity: "low",
					File: "https://example.com/app.js", Line: 30, Value: "10.1.2.3",
					Semantic: &SemanticNote{Judged: true, IsSensitive: false, Reason: "仅内网地址，无凭证", Confidence: 0.6},
				},
			},
			Endpoints: []JSEndpoint{
				{Path: "/api/v1/users", Count: 5},
				{Path: "/api/admin/deleteAll", Count: 1},
			},
		},
	}
}

func sampleReport(t *testing.T) *Report {
	t.Helper()
	r := New("scanner", "0.1.0")
	r.Fingerprints = "内置指纹库（3373 条）"
	r.Semantic = "已启用（deepseek-chat）"
	r.Args = "scanner -u example.com"
	r.Targets = []*TargetReport{sampleTarget(), {Target: "https://dead.example", Error: "连接超时"}}
	r.Finalize(3 * time.Second)
	return r
}

func TestSeverityHelpers(t *testing.T) {
	order := []string{"critical", "high", "medium", "low", "info"}
	for i := 1; i < len(order); i++ {
		if SeverityRank(order[i-1]) >= SeverityRank(order[i]) {
			t.Errorf("排序错误: %s 应比 %s 更严重", order[i-1], order[i])
		}
	}
	// 未知级别按 info 处理
	if SeverityRank("unknown") != SeverityRank("info") {
		t.Errorf("未知级别 rank = %d, want 与 info 相同", SeverityRank("unknown"))
	}
	if got := SeverityDisplay("critical"); got != "严重" {
		t.Errorf("critical → %q, want 严重", got)
	}
	if got := SeverityDisplay("HIGH"); got != "高危" {
		t.Errorf("大小写不敏感映射失败: %q", got)
	}
	if got := SeverityDisplay("bogus"); got != "信息" {
		t.Errorf("未知级别 → %q, want 信息", got)
	}
}

func TestFinalizeSummaryCounts(t *testing.T) {
	r := sampleReport(t)
	s := r.Summary
	if s.Targets != 2 || s.TargetsOK != 1 || s.TargetsFailed != 1 {
		t.Errorf("目标统计 = %+v", s)
	}
	if s.Fingerprints != 1 || s.Exposures != 2 || s.JSFindings != 2 || s.Endpoints != 2 {
		t.Errorf("发现统计 = %+v", s)
	}
	// 1 critical + 2 high + 1 low
	if s.Critical != 1 || s.High != 2 || s.Low != 1 {
		t.Errorf("级别统计 = critical:%d high:%d low:%d, want 1/2/1", s.Critical, s.High, s.Low)
	}
	if s.Requests != 23 {
		t.Errorf("Requests = %d, want 23", s.Requests)
	}
	if s.Duration != "3s" {
		t.Errorf("Duration = %q, want 3s", s.Duration)
	}
}

func TestFinalizeSortsExposuresBySeverity(t *testing.T) {
	r := sampleReport(t)
	ex := r.Targets[0].Exposures
	if len(ex) != 2 {
		t.Fatalf("exposures = %d", len(ex))
	}
	if ex[0].Severity != "critical" {
		t.Errorf("首个 = %s, want critical（更严重的排前）", ex[0].Severity)
	}
}

func TestFinalizeSortsJSFindingsBySeverity(t *testing.T) {
	r := sampleReport(t)
	fs := r.Targets[0].JS.Findings
	if fs[0].Severity != "high" {
		t.Errorf("首个 = %s, want high", fs[0].Severity)
	}
}

func TestHighestSeverity(t *testing.T) {
	r := sampleReport(t)
	if got := r.Targets[0].HighestSeverity(); got != string(SevCritical) {
		t.Errorf("HighestSeverity = %q, want critical", got)
	}
	if got := (&TargetReport{}).HighestSeverity(); got != "" {
		t.Errorf("空目标 = %q, want 空", got)
	}
}

func TestFromFingerprintMatches(t *testing.T) {
	rule := fingerprint.Rule{ID: "nacos", Name: "Nacos", Product: "nacos", Vendor: "alibaba"}
	matches := []fingerprint.Match{{Rule: &rule, Path: "/", URL: "https://x/", Via: "landing", Evidence: "word:x"}}
	got := FromFingerprintMatches(matches)
	if len(got) != 1 || got[0].ID != "nacos" || got[0].Display() != "nacos" {
		t.Fatalf("got = %+v", got)
	}
	if got[0].Vendor != "alibaba" || got[0].Via != "landing" {
		t.Errorf("got = %+v", got[0])
	}
	// nil Rule 应被跳过而不是 panic
	if out := FromFingerprintMatches([]fingerprint.Match{{Rule: nil}}); len(out) != 0 {
		t.Errorf("nil Rule 应被跳过, got %+v", out)
	}
}

func TestFromProbeFindings(t *testing.T) {
	spec := probe.Spec{Path: "/actuator/env", Name: "Actuator 环境变量", Severity: "HIGH"}
	got := FromProbeFindings([]probe.Finding{{Family: "spring", Spec: spec, URL: "https://x/actuator/env", Status: 200, Evidence: "matcher:propertySources"}})
	if len(got) != 1 {
		t.Fatalf("got = %+v", got)
	}
	if got[0].Name != "Actuator 环境变量" || got[0].Path != "/actuator/env" {
		t.Errorf("got = %+v", got[0])
	}
}

func TestFromJSAuditWithAndWithoutVerdicts(t *testing.T) {
	js := &jsaudit.Report{
		Assets: []jsaudit.Asset{
			{URL: "https://x/a.js", Source: "external", Code: []byte("x")},
			{URL: "https://x/a.js.map", Source: "sourcemap", Code: []byte("y")},
		},
		Pages: []string{"https://x/"},
		Findings: []jsaudit.Finding{{
			Category: jsaudit.CatCredential, Severity: jsaudit.SevHigh,
			RuleID: "auth-basic", File: "https://x/a.js", Source: "external", Line: 3,
			Value: "YWRtaW46YWJjZEAxMjM0", Decoded: "admin:abcd@1234", Match: "Authorization:Basic ...", Entropy: 3.64,
		}},
		Endpoints: []jsaudit.Endpoint{{Path: "/api/x", Count: 2}},
	}

	// 无语义层
	sec := FromJSAudit(js, nil)
	if sec == nil {
		t.Fatal("sec = nil")
	}
	if sec.AssetsScanned != 2 || sec.SourceMapHits != 1 {
		t.Errorf("统计 = assets:%d sourcemap:%d", sec.AssetsScanned, sec.SourceMapHits)
	}
	if len(sec.Findings) != 1 || sec.Findings[0].Category != "硬编码凭证" {
		t.Fatalf("findings = %+v", sec.Findings)
	}
	if sec.Findings[0].CategoryKey != "hardcoded-credential" {
		t.Errorf("CategoryKey = %q", sec.Findings[0].CategoryKey)
	}
	if sec.Findings[0].Semantic != nil {
		t.Error("未传 verdicts 时 Semantic 应为 nil")
	}
	if len(sec.Endpoints) != 1 || sec.Endpoints[0].Count != 2 {
		t.Errorf("endpoints = %+v", sec.Endpoints)
	}

	// 带语义层：查询 ID 必须与 jsaudit.SnippetID / report.EndpointID 对齐
	wantSnippet := jsaudit.SnippetID(js.Findings[0])
	wantEndpoint := EndpointID("/api/x")
	queried := map[string]bool{}
	sec2 := FromJSAudit(js, func(id string) *SemanticNote {
		queried[id] = true
		return &SemanticNote{Judged: true, IsSensitive: true, Reason: "r", Confidence: 0.9}
	})
	if !queried[wantSnippet] {
		t.Errorf("未用 jsaudit.SnippetID 查询，实际查询 = %v, want 含 %q", queried, wantSnippet)
	}
	if !queried[wantEndpoint] {
		t.Errorf("未用 report.EndpointID 查询接口，实际查询 = %v, want 含 %q", queried, wantEndpoint)
	}
	if sec2.Findings[0].Semantic == nil || !sec2.Findings[0].Semantic.IsSensitive {
		t.Errorf("semantic = %+v", sec2.Findings[0].Semantic)
	}
}

func TestExtractTitle(t *testing.T) {
	cases := map[string]string{
		"<html><title>Nacos</title></html>":  "Nacos",
		"<TITLE  >  spaced   title </TITLE>": "spaced title",
		"<html>no title</html>":              "",
		"<title>换\n行\t制表</title>":            "换 行 制表",
	}
	for in, want := range cases {
		if got := ExtractTitle([]byte(in)); got != want {
			t.Errorf("ExtractTitle(%q) = %q, want %q", in, got, want)
		}
	}
	long := "<title>" + strings.Repeat("字", 300) + "</title>"
	if got := ExtractTitle([]byte(long)); len([]rune(got)) > 130 {
		t.Errorf("超长标题未截断: %d runes", len([]rune(got)))
	}
}

func TestWriteJSONRoundTrips(t *testing.T) {
	r := sampleReport(t)
	var buf bytes.Buffer
	if err := r.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var back Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("回读失败: %v\n%s", err, buf.String())
	}
	if back.Summary.Targets != 2 || back.Summary.Critical != 1 {
		t.Errorf("回读汇总 = %+v", back.Summary)
	}
	if len(back.Targets) != 2 || back.Targets[0].JS == nil {
		t.Fatalf("回读 targets = %+v", back.Targets)
	}
	if back.Targets[0].JS.Findings[0].Semantic == nil {
		t.Error("语义结论未写入 JSON")
	}
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Error("JSON 输出应以换行结尾")
	}
}

func TestWriteJSONFileCreatesDirs(t *testing.T) {
	r := sampleReport(t)
	dir := filepath.Join("..", "..", ".cache", "testtmp", "reports")
	path := filepath.Join(dir, "r.json")
	t.Cleanup(func() { os.RemoveAll(dir) })

	if err := r.WriteJSONFile(path); err != nil {
		t.Fatalf("WriteJSONFile: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !json.Valid(data) {
		t.Error("写出的不是合法 JSON")
	}
}

func TestWriteTerminalWithoutColorHasNoANSI(t *testing.T) {
	r := sampleReport(t)
	var buf bytes.Buffer
	if err := r.WriteTerminal(&buf, TerminalOptions{Color: false}); err != nil {
		t.Fatalf("WriteTerminal: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b[") {
		t.Error("Color=false 时不应出现 ANSI 转义序列")
	}
	for _, want := range []string{
		"scanner 0.1.0", "example.com", "指纹", "暴露面", "JS 审计",
		"admin:abcd@1234", "确认敏感", "/api/v1/users", "汇总", "连接超时",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("终端输出缺少 %q\n---\n%s", want, out)
		}
	}
}

func TestWriteTerminalWithColorHasANSI(t *testing.T) {
	r := sampleReport(t)
	var buf bytes.Buffer
	if err := r.WriteTerminal(&buf, TerminalOptions{Color: true}); err != nil {
		t.Fatalf("WriteTerminal: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "\x1b[") {
		t.Error("Color=true 时应出现 ANSI 转义序列")
	}
	// 高危/严重必须有醒目标注（红底或红色）
	if !strings.Contains(out, ansiRedBG) && !strings.Contains(out, ansiRed) {
		t.Error("高危/严重级别缺少红色标注")
	}
}

func TestWriteTerminalHidesEndpointOverflow(t *testing.T) {
	r := sampleReport(t)
	var eps []JSEndpoint
	for i := 0; i < 30; i++ {
		eps = append(eps, JSEndpoint{Path: "/api/x"})
	}
	r.Targets[0].JS.Endpoints = eps
	r.Finalize(time.Second)

	var buf bytes.Buffer
	if err := r.WriteTerminal(&buf, TerminalOptions{}); err != nil {
		t.Fatalf("WriteTerminal: %v", err)
	}
	if !strings.Contains(buf.String(), "其余 10 条见 JSON/HTML 报告") {
		t.Error("接口过多时终端应提示其余条目见报告文件")
	}
}

func TestWriteHTMLIsSelfContainedAndEscaped(t *testing.T) {
	r := sampleReport(t)
	// 注入一段恶意内容，验证模板转义
	r.Targets[0].Title = `<script>alert(1)</script>`
	r.Targets[0].JS.Findings[0].Evidence = `<img src=x onerror=alert(2)>`

	var buf bytes.Buffer
	if err := r.WriteHTML(&buf); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()

	if !strings.HasPrefix(out, "<!DOCTYPE html>") {
		t.Error("缺少 DOCTYPE")
	}
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("HTML 未转义 <script>，存在 XSS 风险")
	}
	if strings.Contains(out, "<img src=x onerror=alert(2)>") {
		t.Error("HTML 未转义 onerror 属性")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("期望看到转义后的 <script> 文本")
	}
	// 自包含：不引用任何外部资源
	for _, bad := range []string{"http://", "https://cdn", "<link rel=\"stylesheet\"", "<script src="} {
		if strings.Contains(out, bad) {
			t.Errorf("HTML 含外部资源引用 %q，应完全自包含", bad)
		}
	}
	for _, want := range []string{"scanner 扫描报告", "汇总", "硬编码凭证", "admin:abcd@1234", "确认敏感", "sev-critical", "sev-high"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML 缺少 %q", want)
		}
	}
}

func TestWriteHTMLFile(t *testing.T) {
	r := sampleReport(t)
	dir := filepath.Join("..", "..", ".cache", "testtmp", "reports")
	path := filepath.Join(dir, "r.html")
	t.Cleanup(func() { os.RemoveAll(dir) })

	if err := r.WriteHTMLFile(path); err != nil {
		t.Fatalf("WriteHTMLFile: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Contains(data, []byte("</html>")) {
		t.Error("HTML 未正常结束")
	}
}

func TestReportWithoutFindings(t *testing.T) {
	r := New("scanner", "0.1.0")
	r.Targets = []*TargetReport{{Target: "https://clean.example", Status: 200, Requests: 5}}
	r.Finalize(time.Second)

	var buf bytes.Buffer
	if err := r.WriteTerminal(&buf, TerminalOptions{}); err != nil {
		t.Fatalf("WriteTerminal: %v", err)
	}
	if !strings.Contains(buf.String(), "未发现风险项") {
		t.Errorf("无发现时应提示未发现风险项\n%s", buf.String())
	}

	var hbuf bytes.Buffer
	if err := r.WriteHTML(&hbuf); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	if !strings.Contains(hbuf.String(), "未命中任何指纹") {
		t.Error("HTML 应说明未命中指纹")
	}
}

func TestFromJSAuditAttachesEndpointVerdicts(t *testing.T) {
	js := &jsaudit.Report{Endpoints: []jsaudit.Endpoint{{Path: "/api/admin/deleteAll", Count: 1}}}
	wantID := EndpointID("/api/admin/deleteAll")
	sec := FromJSAudit(js, func(id string) *SemanticNote {
		if id != wantID {
			t.Errorf("查询 ID = %q, want %q", id, wantID)
		}
		return &SemanticNote{Judged: true, IsSensitive: true, Reason: "删除类管理接口", Confidence: 0.9}
	})
	ep := sec.Endpoints[0]
	if ep.Semantic == nil || !ep.Semantic.IsSensitive {
		t.Fatalf("endpoint semantic = %+v", ep.Semantic)
	}

	// 终端与 HTML 都应标出高危接口
	var buf bytes.Buffer
	r := New("scanner", "0.1.0")
	r.Targets = []*TargetReport{{Target: "https://x", Status: 200, JS: sec}}
	r.Finalize(time.Second)
	if err := r.WriteTerminal(&buf, TerminalOptions{}); err != nil {
		t.Fatalf("WriteTerminal: %v", err)
	}
	if !strings.Contains(buf.String(), "高危接口") {
		t.Error("终端未标出高危接口")
	}
	var hbuf bytes.Buffer
	if err := r.WriteHTML(&hbuf); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	if !strings.Contains(hbuf.String(), "高危接口") {
		t.Error("HTML 未标出高危接口")
	}
}

// 目标站点常见非 UTF-8 字节（GBK 页面、乱码），报告必须仍然可读。
func TestReportIsValidUTF8WithNonUTF8Input(t *testing.T) {
	// 一个被切成半个的汉字 + 非法字节，模拟按字节截断的后果
	bad := "测试"[:len("测试")-1] + "\xff\xfe" + "正常"
	r := New("scanner", "0.1.0")
	r.Targets = []*TargetReport{{
		Target: "https://x",
		Status: 200,
		Title:  bad,
		Server: bad,
		Fingerprints: []FingerprintHit{
			{ID: bad, Product: bad, Evidence: bad},
		},
		Exposures: []Exposure{{Name: bad, Severity: "high", Path: bad, Evidence: bad}},
		JS: &JSSection{
			Findings: []JSFinding{{
				Category: bad, CategoryKey: "x", Severity: "high",
				File: bad, Value: bad, Decoded: bad, Evidence: bad, Context: bad, Note: bad,
			}},
			Endpoints: []JSEndpoint{{Path: bad}},
			Pages:     []string{bad},
			Notes:     []string{bad},
		},
		Notes: []string{bad},
	}}
	r.Finalize(time.Second)

	var hbuf bytes.Buffer
	if err := r.WriteHTML(&hbuf); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	if !utf8.Valid(hbuf.Bytes()) {
		t.Error("HTML 报告含非法 UTF-8 字节，整个文件将无法解码")
	}

	var jbuf bytes.Buffer
	if err := r.WriteJSON(&jbuf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !utf8.Valid(jbuf.Bytes()) {
		t.Error("JSON 报告含非法 UTF-8 字节")
	}
	if !json.Valid(jbuf.Bytes()) {
		t.Error("JSON 报告不是合法 JSON")
	}

	var tbuf bytes.Buffer
	if err := r.WriteTerminal(&tbuf, TerminalOptions{}); err != nil {
		t.Fatalf("WriteTerminal: %v", err)
	}
	if !utf8.Valid(tbuf.Bytes()) {
		t.Error("终端输出含非法 UTF-8 字节")
	}
}

func TestSuspendedAndFailureRendering(t *testing.T) {
	r := New("scanner", "0.1.0")
	r.Targets = []*TargetReport{
		{Target: "https://susp.example", Status: 200,
			Suspended: true, SuspendedReason: "页面内容含「系统暂停访问」",
			Notes: []string{"目标疑似暂停服务，本次结果不完整"}},
		{Target: "https://t.example", Error: `dial tcp 1.2.3.4:443: i/o timeout`, FailureKind: "timeout"},
		{Target: "https://t2.example", Error: `connectex: actively refused`, FailureKind: "timeout"},
		{Target: "https://r.example", Error: `actively refused`, FailureKind: "refused"},
	}
	r.Finalize(time.Second)

	if r.Summary.TargetsFailed != 3 {
		t.Fatalf("TargetsFailed = %d, want 3", r.Summary.TargetsFailed)
	}
	if r.Summary.FailureReasons["timeout"] != 2 || r.Summary.FailureReasons["refused"] != 1 {
		t.Errorf("FailureReasons = %v, want timeout×2 refused×1", r.Summary.FailureReasons)
	}

	var buf bytes.Buffer
	if err := r.WriteTerminal(&buf, TerminalOptions{}); err != nil {
		t.Fatalf("WriteTerminal: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"目标暂停服务，结果不完整", "失败原因", "[timeout]", "[refused]"} {
		if !strings.Contains(out, want) {
			t.Errorf("终端输出缺少 %q\n%s", want, out)
		}
	}
	// 超时占 2/3 ≥ 60% → 应给出可操作提示
	if !strings.Contains(out, "超时占多数") {
		t.Errorf("超时占多数时应给出提示\n%s", out)
	}

	var hbuf bytes.Buffer
	if err := r.WriteHTML(&hbuf); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := hbuf.String()
	for _, want := range []string{"warn", "目标暂停服务，结果不完整", "失败原因分布"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML 缺少 %q", want)
		}
	}

	var jbuf bytes.Buffer
	if err := r.WriteJSON(&jbuf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var back Report
	if err := json.Unmarshal(jbuf.Bytes(), &back); err != nil {
		t.Fatalf("回读失败: %v", err)
	}
	if !back.Targets[0].Suspended || back.Targets[0].SuspendedReason == "" {
		t.Errorf("JSON 未保留 suspended 字段: %+v", back.Targets[0])
	}
	if back.Targets[1].FailureKind != "timeout" {
		t.Errorf("JSON failure_kind = %q, want timeout", back.Targets[1].FailureKind)
	}
	if back.Summary.FailureReasons["refused"] != 1 {
		t.Errorf("JSON failure_reasons = %v", back.Summary.FailureReasons)
	}
}

func TestNoFailureReasonsWhenAllOK(t *testing.T) {
	r := New("scanner", "0.1.0")
	r.Targets = []*TargetReport{{Target: "https://ok.example", Status: 200}}
	r.Finalize(time.Second)
	if len(r.Summary.FailureReasons) != 0 {
		t.Errorf("全部成功时不应有失败原因分布: %v", r.Summary.FailureReasons)
	}
	var buf bytes.Buffer
	if err := r.WriteTerminal(&buf, TerminalOptions{}); err != nil {
		t.Fatalf("WriteTerminal: %v", err)
	}
	if strings.Contains(buf.String(), "失败原因") {
		t.Error("全部成功时不应输出失败原因行")
	}
}
