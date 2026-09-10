package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/einmsrf/scanner/pkg/report"
)

// tmpDir 返回项目目录内的临时目录（遵守 DESIGN.md 第 2.0 节：不写项目外）。
func tmpDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", ".cache", "testtmp", t.Name())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// vulnServer 模拟一个带指纹、暴露面与 JS 敏感信息的目标。
func vulnServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><title>nacos</title>
				<script src="/app.js"></script></head>
				<body>nacos console</body></html>`)
		case "/app.js":
			fmt.Fprint(w, `
var cfg = {
  Authorization: "Basic YWRtaW46YWJjZEAxMjM0",
  host: "10.20.30.40"
};
// 测试账号: testadmin / Test@123456
fetch("/api/v2/internal/users");
`)
		case "/.git/HEAD":
			fmt.Fprint(w, "ref: refs/heads/main\n")
		case "/actuator/env":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"propertySources":[{"name":"systemProperties"}]}`)
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, "<html>404 not found</html>")
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestRunVersionAndHelp(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"version"}, {"-v"}} {
		var out, errBuf bytes.Buffer
		if code := run(args, &out, &errBuf); code != 0 {
			t.Errorf("run(%v) = %d, want 0", args, code)
		}
		if !strings.Contains(out.String(), "scanner") {
			t.Errorf("run(%v) 输出 = %q, want 含版本", args, out.String())
		}
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"help"}, &out, &errBuf); code != 0 {
		t.Errorf("help 退出码 = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "用法") {
		t.Error("help 未输出用法说明")
	}
	// -h 走 flag 包时会返回 0（我们的 run 自己处理 help/-h/--help）
	if code := run([]string{"--help"}, &out, &errBuf); code != 0 {
		t.Errorf("--help 退出码 = %d, want 0", code)
	}
}

func TestRunWithoutTargetsFails(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--quiet"}, &out, &errBuf)
	if code == 0 {
		t.Error("无目标时退出码 = 0, want 非 0")
	}
	if !strings.Contains(errBuf.String(), "没有可扫描的目标") {
		t.Errorf("stderr = %q", errBuf.String())
	}
}

func TestRunScanEndToEndWritesReports(t *testing.T) {
	srv := vulnServer(t)
	dir := tmpDir(t)
	jsonPath := filepath.Join(dir, "out.json")
	htmlPath := filepath.Join(dir, "out.html")

	var out, errBuf bytes.Buffer
	code := run([]string{
		"-u", srv.URL,
		"--rate", "-1",
		"--max-requests", "200",
		"--out", filepath.Join(dir, "reports"),
		"--json", jsonPath,
		"--html", htmlPath,
		"--no-semantic",
	}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("退出码 = %d, want 0\nstderr: %s\nstdout: %s", code, errBuf.String(), out.String())
	}

	// JSON 报告
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("读取 JSON 报告: %v", err)
	}
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("JSON 报告解析失败: %v\n%s", err, data)
	}
	if len(rep.Targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(rep.Targets))
	}
	tr := rep.Targets[0]
	if tr.Error != "" {
		t.Fatalf("目标扫描失败: %s", tr.Error)
	}
	if tr.Status != 200 {
		t.Errorf("status = %d, want 200", tr.Status)
	}

	// 指纹：nacos
	var gotNacos bool
	for _, f := range tr.Fingerprints {
		if f.ID == "alibaba-nacos" {
			gotNacos = true
		}
	}
	if !gotNacos {
		t.Errorf("未命中 nacos 指纹: %+v", tr.Fingerprints)
	}

	// 暴露面：通用字典应命中 /.git/HEAD
	var gotGit bool
	for _, e := range tr.Exposures {
		if e.Path == "/.git/HEAD" {
			gotGit = true
		}
	}
	if !gotGit {
		t.Errorf("未命中 /.git/HEAD 暴露面: %+v", tr.Exposures)
	}

	// JS：Basic 头解出 user:pass；接口路径被提取
	if tr.JS == nil {
		t.Fatal("JS 审计结果为空")
	}
	var gotCred bool
	for _, f := range tr.JS.Findings {
		if strings.Contains(f.Decoded, "admin:abcd@1234") {
			gotCred = true
		}
	}
	if !gotCred {
		t.Errorf("未检出并解码 Basic 凭证: %+v", tr.JS.Findings)
	}
	var gotEP bool
	for _, e := range tr.JS.Endpoints {
		if e.Path == "/api/v2/internal/users" {
			gotEP = true
		}
	}
	if !gotEP {
		t.Errorf("未提取到接口路径: %+v", tr.JS.Endpoints)
	}

	// HTML 报告
	hdata, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("读取 HTML 报告: %v", err)
	}
	if !bytes.Contains(hdata, []byte("</html>")) {
		t.Error("HTML 报告不完整")
	}

	// 终端输出应提示报告路径
	if !strings.Contains(out.String(), "JSON 报告:") || !strings.Contains(out.String(), "HTML 报告:") {
		t.Errorf("stdout 未提示报告路径: %s", out.String())
	}
	// --no-semantic 应在报告里说明
	if !strings.Contains(rep.Semantic, "no-semantic") {
		t.Errorf("语义层状态 = %q, want 说明按 --no-semantic 关闭", rep.Semantic)
	}
}

func TestRunScanJSONToStdoutIsPureJSON(t *testing.T) {
	srv := vulnServer(t)
	var out, errBuf bytes.Buffer
	code := run([]string{
		"-u", srv.URL,
		"--rate", "-1",
		"--max-requests", "200",
		"--json", "-",
		"--no-js",
		"--no-semantic",
	}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("退出码 = %d, stderr: %s", code, errBuf.String())
	}
	// 标准输出必须是可直接管道的纯 JSON（不含终端报告）
	if !json.Valid(out.Bytes()) {
		t.Fatalf("stdout 不是合法 JSON:\n%s", out.String())
	}
	if strings.Contains(out.String(), "── 汇总") {
		t.Error("--json - 时不应输出终端报告")
	}
}

func TestRunScanListFileAndInvalidLines(t *testing.T) {
	srv := vulnServer(t)
	dir := tmpDir(t)
	listPath := filepath.Join(dir, "targets.txt")
	content := "# 注释行\n\n" + srv.URL + "\nnot a valid target:::\n" + srv.URL + "\n"
	if err := os.WriteFile(listPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var out, errBuf bytes.Buffer
	code := run([]string{
		"-l", listPath, "-u", srv.URL,
		"--rate", "-1", "--max-requests", "200",
		"--quiet", "--out", filepath.Join(dir, "reports"),
		"--json", filepath.Join(dir, "r.json"), "--no-js", "--no-probe", "--no-semantic",
	}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("退出码 = %d, stderr: %s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "忽略无效行") {
		t.Errorf("stderr 应提示忽略无效行: %s", errBuf.String())
	}

	data, err := os.ReadFile(filepath.Join(dir, "r.json"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	// 同一目标（-u 与文件里重复）应去重为一个
	if len(rep.Targets) != 1 {
		t.Errorf("targets = %d, want 1（重复目标应去重）", len(rep.Targets))
	}
}

func TestRunScanNoJSNoProbe(t *testing.T) {
	srv := vulnServer(t)
	dir := tmpDir(t)
	var out, errBuf bytes.Buffer
	code := run([]string{
		"-u", srv.URL, "--rate", "-1", "--quiet",
		"--out", filepath.Join(dir, "reports"),
		"--json", filepath.Join(dir, "r.json"),
		"--no-js", "--no-probe", "--no-semantic",
	}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("退出码 = %d, stderr: %s", code, errBuf.String())
	}
	data, _ := os.ReadFile(filepath.Join(dir, "r.json"))
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	tr := rep.Targets[0]
	if tr.JS != nil {
		t.Error("--no-js 时不应有 JS 审计结果")
	}
	if len(tr.Exposures) != 0 {
		t.Errorf("--no-probe 时不应有暴露面: %+v", tr.Exposures)
	}
	// 指纹仍应工作
	if len(tr.Fingerprints) == 0 {
		t.Error("--no-js/--no-probe 不应影响指纹识别")
	}
	// 请求数应明显少于完整扫描
	if tr.Requests > 10 {
		t.Errorf("Requests = %d, 跳过 JS/探测后应很少", tr.Requests)
	}
}

func TestRunScanUnreachableTargetReportsError(t *testing.T) {
	dir := tmpDir(t)
	var out, errBuf bytes.Buffer
	code := run([]string{
		"-u", "127.0.0.1:1", "--rate", "-1", "--timeout", "2s",
		"--quiet", "--out", filepath.Join(dir, "reports"),
		"--json", filepath.Join(dir, "r.json"), "--no-semantic",
	}, &out, &errBuf)
	// 扫描流程本身应正常结束（退出码 0），失败信息写进报告
	if code != 0 {
		t.Fatalf("退出码 = %d, want 0（单目标失败不应让整个进程失败）", code)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "r.json"))
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(rep.Targets) != 1 || rep.Targets[0].Error == "" {
		t.Errorf("目标应有错误信息: %+v", rep.Targets)
	}
	if rep.Summary.TargetsFailed != 1 {
		t.Errorf("TargetsFailed = %d, want 1", rep.Summary.TargetsFailed)
	}
}

func TestRunScanBothProtocols(t *testing.T) {
	srv := vulnServer(t)
	dir := tmpDir(t)
	var out, errBuf bytes.Buffer
	code := run([]string{
		"-u", srv.URL, "--both", "--rate", "-1", "--max-requests", "300",
		"--quiet", "--out", filepath.Join(dir, "reports"),
		"--json", filepath.Join(dir, "r.json"),
		"--no-js", "--no-probe", "--no-semantic",
	}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("退出码 = %d, stderr: %s", code, errBuf.String())
	}
	data, _ := os.ReadFile(filepath.Join(dir, "r.json"))
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	// 明文服务只有 http 可用，--both 也应只得到 1 个目标条目
	if len(rep.Targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(rep.Targets))
	}
	if rep.Targets[0].Error != "" {
		t.Fatalf("目标失败: %s", rep.Targets[0].Error)
	}
}

func TestUpdateFromSourceDir(t *testing.T) {
	dir := tmpDir(t)
	tplDir := filepath.Join(dir, "web-fingerprint", "demo")
	if err := os.MkdirAll(tplDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(tplDir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	write("a.yaml", "id: demo-a\ninfo:\n  name: DemoA\nhttp:\n- path: ['{{BaseURL}}/']\n  matchers:\n  - type: word\n    words: [alpha]\n")
	write("b.yaml", "id: demo-b\ninfo:\n  name: DemoB\nhttp:\n- path: ['{{BaseURL}}/b']\n  matchers:\n  - type: favicon\n    hash: [715c49c5512d763084a4082c27d935e1]\n")

	outPath := filepath.Join(dir, "fingerprints.json")
	var out, errBuf bytes.Buffer
	// --source-dir 指向包含 web-fingerprint 的目录，应自动下钻
	code := run([]string{"update", "--source-dir", dir, "--out", outPath}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("update 退出码 = %d, stderr: %s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "已写入") {
		t.Errorf("stdout = %q, want 提示已写入", out.String())
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("读取产物: %v", err)
	}
	var lib struct {
		Count int `json:"count"`
		Rules []struct {
			ID    string   `json:"id"`
			Paths []string `json:"paths"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(data, &lib); err != nil {
		t.Fatalf("产物不是合法 JSON: %v", err)
	}
	if lib.Count != 2 {
		t.Fatalf("count = %d, want 2", lib.Count)
	}
	if lib.Rules[0].ID != "demo-a" || lib.Rules[1].ID != "demo-b" {
		t.Errorf("规则未按 ID 排序: %+v", lib.Rules)
	}
	// 来源应记录为本地目录
	if !strings.Contains(string(data), "local:") {
		t.Error("产物应记录本地来源")
	}
}

func TestUpdateDryRunDoesNotWrite(t *testing.T) {
	dir := tmpDir(t)
	writeTemplate(t, dir, "x.yaml")
	outPath := filepath.Join(dir, "should-not-exist.json")

	var out, errBuf bytes.Buffer
	code := run([]string{"update", "--source-dir", dir, "--out", outPath, "--dry-run"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("退出码 = %d, stderr: %s", code, errBuf.String())
	}
	if _, err := os.Stat(outPath); err == nil {
		t.Error("--dry-run 不应写文件")
	}
	if !strings.Contains(out.String(), "dry-run") {
		t.Errorf("stdout 应说明 dry-run: %s", out.String())
	}
}

func TestUpdateMissingSourceDirFails(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"update", "--source-dir", filepath.Join("..", "..", ".cache", "does-not-exist")}, &out, &errBuf)
	if code == 0 {
		t.Error("目录不存在时退出码 = 0, want 非 0")
	}
	if !strings.Contains(errBuf.String(), "模板目录不可用") {
		t.Errorf("stderr = %q", errBuf.String())
	}
}

func writeTemplate(t *testing.T, dir, name string) {
	t.Helper()
	body := "id: t\ninfo:\n  name: T\nhttp:\n- path: ['{{BaseURL}}/']\n  matchers:\n  - type: word\n    words: [hello]\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestUpdateFromRealCacheIfPresent(t *testing.T) {
	// 本地 .cache/FingerprintHub 存在时做一次真实转换（CI 无此目录则跳过）
	cache := filepath.Join("..", "..", ".cache", "FingerprintHub")
	if _, err := os.Stat(cache); err != nil {
		t.Skipf("本地无 FingerprintHub 缓存，跳过: %v", err)
	}
	dir := tmpDir(t)
	outPath := filepath.Join(dir, "fingerprints.json")

	var out, errBuf bytes.Buffer
	code := run([]string{"update", "--source-dir", cache, "--out", outPath}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("退出码 = %d, stderr: %s", code, errBuf.String())
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("读取产物: %v", err)
	}
	var lib struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(data, &lib); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if lib.Count < 3000 {
		t.Errorf("count = %d, want >= 3000", lib.Count)
	}
	t.Logf("真实指纹库转换结果: %d 条规则", lib.Count)
}
