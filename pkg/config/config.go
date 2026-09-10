// Package config 负责配置文件（config.yaml）的查找、加载与默认值填充。
//
// 查找顺序（DESIGN.md 第 4 节）：--config 指定 > 当前目录 config.yaml > 可执行文件同目录 config.yaml。
// 命令行参数优先级高于配置文件，由 CLI 层在 Load 之后覆盖对应字段。
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// 默认值。
const (
	DefaultBaseURL     = "https://api.deepseek.com/v1"
	DefaultModel       = "deepseek-chat"
	DefaultTimeout     = 10 * time.Second
	DefaultLLMTimeout  = 30 * time.Second
	DefaultConcurrency = 10
	DefaultQPS         = 5
	DefaultMaxRounds   = 100 // 单目标请求预算，与 httpx.DefaultMaxRequests 保持一致

	MaxConcurrency = 200
	MaxQPS         = 1000
)

// Duration 是可从 "30s"/"1m"/裸数字（按秒）解析的时长。
type Duration time.Duration

// Std 转成标准库时长。
func (d Duration) Std() time.Duration { return time.Duration(d) }

// UnmarshalYAML 支持 `30s` 这类字符串与 `30`（秒）两种写法。
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err == nil {
		s = strings.TrimSpace(s)
		if s == "" {
			*d = 0
			return nil
		}
		if n, err := strconv.Atoi(s); err == nil {
			*d = Duration(time.Duration(n) * time.Second)
			return nil
		}
		v, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("config: 无法解析时长 %q（示例：10s、1m30s）: %w", s, err)
		}
		*d = Duration(v)
		return nil
	}
	var n int
	if err := value.Decode(&n); err == nil {
		*d = Duration(time.Duration(n) * time.Second)
		return nil
	}
	return fmt.Errorf("config: 时长格式无效: %q", value.Value)
}

// MarshalYAML 以 "10s" 形式输出。
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// LLM 是语义层配置（OpenAI 兼容接口）。APIKey 为空时语义层自动关闭。
type LLM struct {
	BaseURL string   `yaml:"base_url"`
	APIKey  string   `yaml:"api_key"`
	Model   string   `yaml:"model"`
	Timeout Duration `yaml:"timeout"`
}

// Scan 是扫描行为配置。
type Scan struct {
	Concurrency int      `yaml:"concurrency"` // 目标级并发
	QPS         float64  `yaml:"qps"`         // 单目标 QPS
	Timeout     Duration `yaml:"timeout"`     // 单请求超时
}

// Config 是完整配置。
type Config struct {
	LLM   LLM    `yaml:"llm"`
	Proxy string `yaml:"proxy"` // 为空时使用 HTTPS_PROXY/HTTP_PROXY 环境变量
	Scan  Scan   `yaml:"scan"`

	// SourcePath 记录实际加载的配置文件路径，空串表示全部使用默认值。
	SourcePath string `yaml:"-"`
}

// Default 返回带默认值的配置。
func Default() Config {
	return Config{
		LLM: LLM{
			BaseURL: DefaultBaseURL,
			Model:   DefaultModel,
			Timeout: Duration(DefaultLLMTimeout),
		},
		Scan: Scan{
			Concurrency: DefaultConcurrency,
			QPS:         DefaultQPS,
			Timeout:     Duration(DefaultTimeout),
		},
	}
}

// Load 按查找顺序读取配置。explicit 非空时只读该文件，且文件必须存在。
// 返回的 Config 已完成默认值填充与校验。
func Load(explicit string) (Config, error) {
	if explicit != "" {
		cfg, err := loadFile(explicit)
		if err != nil {
			return Config{}, err
		}
		return cfg, nil
	}
	for _, p := range candidatePaths() {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return loadFile(p)
		}
	}
	cfg := Default()
	return cfg, nil
}

// candidatePaths 返回默认查找路径：当前目录 → 可执行文件目录。
func candidatePaths() []string {
	var paths []string
	paths = append(paths, "config.yaml")

	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		p := filepath.Join(dir, "config.yaml")
		if !samePath(p, paths[0]) {
			paths = append(paths, p)
		}
	}
	return paths
}

func samePath(a, b string) bool {
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	if err1 != nil || err2 != nil {
		return a == b
	}
	return aa == bb
}

// loadFile 读取并解析单个配置文件。
func loadFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: 读取 %s 失败: %w", path, err)
	}
	cfg := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // 拼错字段名要报错，避免配置静默失效
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("config: 解析 %s 失败: %w", path, err)
	}
	cfg.SourcePath = path
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("config: %s %w", path, err)
	}
	return cfg, nil
}

// Validate 校验并钳制取值到安全范围。零值字段按默认值补齐。
func (c *Config) Validate() error {
	if strings.TrimSpace(c.LLM.BaseURL) == "" {
		c.LLM.BaseURL = DefaultBaseURL
	}
	if strings.TrimSpace(c.LLM.Model) == "" {
		c.LLM.Model = DefaultModel
	}
	if c.LLM.Timeout <= 0 {
		c.LLM.Timeout = Duration(DefaultLLMTimeout)
	}

	if c.Scan.Concurrency <= 0 {
		c.Scan.Concurrency = DefaultConcurrency
	}
	if c.Scan.Concurrency > MaxConcurrency {
		c.Scan.Concurrency = MaxConcurrency
	}
	if c.Scan.QPS <= 0 {
		c.Scan.QPS = DefaultQPS
	}
	if c.Scan.QPS > MaxQPS {
		c.Scan.QPS = MaxQPS
	}
	if c.Scan.Timeout <= 0 {
		c.Scan.Timeout = Duration(DefaultTimeout)
	}

	if c.Proxy != "" && !strings.Contains(c.Proxy, "://") {
		return fmt.Errorf("proxy 地址需要带协议前缀，例如 http://127.0.0.1:7890（当前 %q）", c.Proxy)
	}
	return nil
}

// SemanticEnabled 判断语义层是否可用（需要 api_key）。
func (c *Config) SemanticEnabled() bool {
	return strings.TrimSpace(c.LLM.APIKey) != ""
}

// MaskedAPIKey 返回脱敏后的 api_key，供日志展示。
func (c *Config) MaskedAPIKey() string {
	k := strings.TrimSpace(c.LLM.APIKey)
	switch {
	case k == "":
		return "(未配置)"
	case len(k) <= 8:
		return "****"
	default:
		return k[:4] + "****" + k[len(k)-4:]
	}
}

// Example 返回 config.yaml.example 的内容。
func Example() string {
	return `# scanner 配置文件示例
# 复制为 config.yaml 后按需修改；config.yaml 已在 .gitignore 中，不会入库。

llm:
  base_url: "https://api.deepseek.com/v1"   # 任何 OpenAI 兼容接口（DeepSeek/通义/Kimi 均可）
  api_key: ""                               # 留空则语义层自动降级为纯正则模式
  model: "deepseek-chat"
  timeout: 30s

proxy: ""                                   # 可选，如 "http://127.0.0.1:7890"；留空则用 HTTPS_PROXY 环境变量

scan:
  concurrency: 10      # 目标级并发
  qps: 5               # 单目标每秒请求数上限
  timeout: 10s         # 单请求超时
`
}
