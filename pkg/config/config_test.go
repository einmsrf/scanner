package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultValues(t *testing.T) {
	c := Default()
	if c.Scan.Concurrency != 10 {
		t.Errorf("Concurrency = %d, want 10", c.Scan.Concurrency)
	}
	if c.Scan.QPS != 5 {
		t.Errorf("QPS = %v, want 5", c.Scan.QPS)
	}
	if c.Scan.Timeout.Std() != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", c.Scan.Timeout.Std())
	}
	if c.SemanticEnabled() {
		t.Error("SemanticEnabled = true, want false（默认无 api_key）")
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestLoadFullConfig(t *testing.T) {
	p := writeTempConfig(t, `
llm:
  base_url: "https://api.moonshot.cn/v1"
  api_key: "sk-test-abcdefghijklmn"
  model: "kimi-k2"
  timeout: 45s

proxy: "http://127.0.0.1:7890"

scan:
  concurrency: 20
  qps: 8
  timeout: 15s
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LLM.BaseURL != "https://api.moonshot.cn/v1" {
		t.Errorf("BaseURL = %q", cfg.LLM.BaseURL)
	}
	if cfg.LLM.Model != "kimi-k2" {
		t.Errorf("Model = %q", cfg.LLM.Model)
	}
	if cfg.LLM.Timeout.Std() != 45*time.Second {
		t.Errorf("LLM.Timeout = %v, want 45s", cfg.LLM.Timeout.Std())
	}
	if cfg.Proxy != "http://127.0.0.1:7890" {
		t.Errorf("Proxy = %q", cfg.Proxy)
	}
	if cfg.Scan.Concurrency != 20 || cfg.Scan.QPS != 8 || cfg.Scan.Timeout.Std() != 15*time.Second {
		t.Errorf("Scan = %+v", cfg.Scan)
	}
	if !cfg.SemanticEnabled() {
		t.Error("SemanticEnabled = false, want true")
	}
	if cfg.SourcePath != p {
		t.Errorf("SourcePath = %q, want %q", cfg.SourcePath, p)
	}
}

func TestLoadPartialConfigKeepsDefaults(t *testing.T) {
	p := writeTempConfig(t, `
scan:
  qps: 3
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Scan.QPS != 3 {
		t.Errorf("QPS = %v, want 3", cfg.Scan.QPS)
	}
	if cfg.Scan.Concurrency != DefaultConcurrency {
		t.Errorf("Concurrency = %d, want 默认 %d", cfg.Scan.Concurrency, DefaultConcurrency)
	}
	if cfg.LLM.BaseURL != DefaultBaseURL {
		t.Errorf("BaseURL = %q, want 默认 %q", cfg.LLM.BaseURL, DefaultBaseURL)
	}
	if cfg.SemanticEnabled() {
		t.Error("未配 api_key 时语义层应关闭")
	}
}

func TestDurationAcceptsBareSeconds(t *testing.T) {
	p := writeTempConfig(t, `
scan:
  timeout: 7
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Scan.Timeout.Std() != 7*time.Second {
		t.Errorf("Timeout = %v, want 7s（裸数字按秒）", cfg.Scan.Timeout.Std())
	}
}

func TestLoadEmptyFileUsesDefaults(t *testing.T) {
	p := writeTempConfig(t, "")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Scan.Concurrency != DefaultConcurrency {
		t.Errorf("Concurrency = %d, want 默认", cfg.Scan.Concurrency)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	p := writeTempConfig(t, `
scan:
  concurrncy: 20
`)
	if _, err := Load(p); err == nil {
		t.Fatal("err = nil, want 未知字段报错（防止拼错静默失效）")
	}
}

func TestLoadRejectsBadDuration(t *testing.T) {
	p := writeTempConfig(t, `
scan:
  timeout: "十秒"
`)
	if _, err := Load(p); err == nil {
		t.Fatal("err = nil, want 时长解析错误")
	}
}

func TestLoadRejectsProxyWithoutScheme(t *testing.T) {
	p := writeTempConfig(t, `
proxy: "127.0.0.1:7890"
`)
	if _, err := Load(p); err == nil {
		t.Fatal("err = nil, want proxy 缺少协议前缀报错")
	}
}

func TestExplicitMissingFileIsError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("err = nil, want 显式指定的文件缺失应报错")
	}
}

func TestValidateClampsRanges(t *testing.T) {
	c := Config{}
	c.Scan.Concurrency = 99999
	c.Scan.QPS = 99999
	c.Scan.Timeout = -1
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.Scan.Concurrency != MaxConcurrency {
		t.Errorf("Concurrency = %d, want 钳制到 %d", c.Scan.Concurrency, MaxConcurrency)
	}
	if c.Scan.QPS != MaxQPS {
		t.Errorf("QPS = %v, want 钳制到 %d", c.Scan.QPS, MaxQPS)
	}
	if c.Scan.Timeout.Std() != DefaultTimeout {
		t.Errorf("Timeout = %v, want 默认 %v", c.Scan.Timeout.Std(), DefaultTimeout)
	}
}

func TestMaskedAPIKey(t *testing.T) {
	c := Config{}
	if got := c.MaskedAPIKey(); got != "(未配置)" {
		t.Errorf("空 key = %q", got)
	}
	c.LLM.APIKey = "sk-1234567890abcdef"
	got := c.MaskedAPIKey()
	if strings.Contains(got, "567890abcd") {
		t.Errorf("脱敏失败，泄漏了中段: %q", got)
	}
	if !strings.HasPrefix(got, "sk-1") || !strings.HasSuffix(got, "cdef") {
		t.Errorf("脱敏结果 = %q, want 保留首尾", got)
	}
	c.LLM.APIKey = "short"
	if got := c.MaskedAPIKey(); got != "****" {
		t.Errorf("短 key = %q, want ****", got)
	}
}

func TestExampleParsesClean(t *testing.T) {
	p := writeTempConfig(t, Example())
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("示例配置应可解析: %v", err)
	}
	if cfg.SemanticEnabled() {
		t.Error("示例中 api_key 为空，语义层应为关闭")
	}
	if cfg.Scan.Concurrency != 10 || cfg.Scan.QPS != 5 {
		t.Errorf("示例 scan = %+v", cfg.Scan)
	}
	if cfg.Proxy != "" {
		t.Errorf("示例 proxy = %q, want 空", cfg.Proxy)
	}
}

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	// 遵守 DESIGN.md 第 2.0 节：临时文件也放在项目目录内。
	dir := filepath.Join("..", "..", ".cache", "testtmp")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	f, err := os.CreateTemp(dir, "config-*.yaml")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := f.WriteString(body); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}
