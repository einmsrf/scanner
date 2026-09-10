// Command scanner 是一个单文件 CLI：输入域名/IP，自动补全 http/https、识别 Web 指纹、
// 探测已知暴露面、审计 JS 中的敏感信息与接口（只分析，绝不主动请求 JS 中发现的接口）。
//
// 本文件只做参数解析与流程编排，核心逻辑都在 pkg/ 下。
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/einmsrf/scanner/pkg/config"
)

// 扫描行为默认值（DESIGN.md 第 9 节）。
const (
	defaultOutDir        = "reports"
	defaultTargetTimeout = 3 * time.Minute // 单目标总耗时上限
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run 是可测试的入口：返回进程退出码。
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "update":
			return runUpdate(args[1:], stdout, stderr)
		case "help", "-h", "--help":
			usage(stdout)
			return 0
		case "version", "-v", "--version":
			fmt.Fprintf(stdout, "scanner %s\n", versionString())
			return 0
		}
	}
	return runScan(args, stdout, stderr)
}

// options 是合并后的运行配置（命令行 > 配置文件 > 默认值）。
type options struct {
	targetsFile string
	url         string

	both     bool
	basePath string

	rate        float64
	concurrency int
	timeout     time.Duration
	proxy       string
	maxRequests int
	targetLimit time.Duration

	outDir   string
	jsonPath string
	htmlPath string

	color     bool
	quiet     bool
	verbose   bool
	noJS      bool
	noProbe   bool
	noSemants bool
	verifyTLS bool
	strictFP  bool

	configPath string
}

// runScan 执行扫描。
func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scanner", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		o       options
		showVer bool
	)
	fs.StringVar(&o.url, "u", "", "单个目标（域名/IP/IP:端口/域名:端口/完整 URL）")
	fs.StringVar(&o.url, "url", "", "同 -u")
	fs.StringVar(&o.targetsFile, "l", "", "目标列表文件（每行一个，# 为注释）")
	fs.StringVar(&o.targetsFile, "list", "", "同 -l")
	fs.BoolVar(&o.both, "both", false, "http 与 https 两个协议都扫描")
	fs.StringVar(&o.basePath, "base-path", "", "手动指定部署 base 路径，如 /oa")
	fs.Float64Var(&o.rate, "rate", 0, "单目标 QPS 上限（覆盖配置）；-1 表示不限速")
	fs.IntVar(&o.concurrency, "concurrency", 0, "目标级并发数（覆盖配置）")
	fs.DurationVar(&o.timeout, "timeout", 0, "单请求超时，如 10s（覆盖配置）")
	fs.StringVar(&o.proxy, "proxy", "", "代理地址，如 http://127.0.0.1:7890（覆盖配置）")
	fs.IntVar(&o.maxRequests, "max-requests", 0, "单目标请求预算上限（默认 100）")
	fs.DurationVar(&o.targetLimit, "target-timeout", defaultTargetTimeout, "单目标总耗时上限")
	fs.StringVar(&o.outDir, "out", defaultOutDir, "报告输出目录")
	fs.StringVar(&o.jsonPath, "json", "", "JSON 报告路径（- 表示输出到标准输出）")
	fs.StringVar(&o.htmlPath, "html", "", "HTML 报告路径")
	fs.BoolVar(&o.quiet, "quiet", false, "不输出终端报告")
	fs.BoolVar(&o.verbose, "verbose", false, "输出更多细节")
	fs.BoolVar(&o.noJS, "no-js", false, "跳过 JS 审计")
	fs.BoolVar(&o.noProbe, "no-probe", false, "跳过暴露面探测")
	fs.BoolVar(&o.noSemants, "no-semantic", false, "禁用语义层（即使配置了 api_key）")
	fs.BoolVar(&o.verifyTLS, "verify-tls", false, "校验证书（默认跳过，目标多为自签）")
	fs.BoolVar(&o.color, "color", o.color, "终端彩色输出（管道/NO_COLOR 下自动关闭）")
	var noColor bool
	fs.BoolVar(&noColor, "no-color", false, "强制关闭彩色输出")
	fs.StringVar(&o.configPath, "config", "", "配置文件路径（默认查找 ./config.yaml）")
	fs.BoolVar(&showVer, "version", false, "打印版本后退出")
	fs.BoolVar(&o.strictFP, "strict-fingerprints", false, "找不到指纹库时报错退出（默认用内置库）")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if showVer {
		fmt.Fprintf(stdout, "scanner %s\n", versionString())
		return 0
	}

	// 配置文件 + 命令行覆盖
	cfg, err := config.Load(o.configPath)
	if err != nil {
		fmt.Fprintf(stderr, "错误: %v\n", err)
		return 1
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if set["rate"] {
		cfg.Scan.QPS = o.rate
	} else {
		o.rate = cfg.Scan.QPS
	}
	if set["concurrency"] {
		cfg.Scan.Concurrency = o.concurrency
	} else {
		o.concurrency = cfg.Scan.Concurrency
	}
	if set["timeout"] {
		cfg.Scan.Timeout = config.Duration(o.timeout)
	} else {
		o.timeout = cfg.Scan.Timeout.Std()
	}
	if set["proxy"] {
		cfg.Proxy = o.proxy
	} else {
		o.proxy = cfg.Proxy
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "错误: %v\n", err)
		return 1
	}

	// 收集目标
	targets, bad, err := collectTargets(o.url, o.targetsFile)
	if err != nil {
		fmt.Fprintf(stderr, "错误: %v\n", err)
		return 1
	}
	for _, b := range bad {
		fmt.Fprintf(stderr, "忽略无效行: %s\n", b)
	}
	if len(targets) == 0 {
		fmt.Fprintln(stderr, "错误: 没有可扫描的目标，请用 -u <目标> 或 -l <文件> 指定")
		fs.Usage()
		return 2
	}

	// 装配各层
	a, err := newApp(cfg, o, stdout, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "错误: %v\n", err)
		return 1
	}
	defer a.close()

	return a.run(stdout, stderr)
}

// versionString 返回版本号，便于测试替换。
func versionString() string { return toolVersion }

// defaultColor 判断是否默认输出彩色：标准输出是终端、且未设置 NO_COLOR 时才着色。
// 输出被重定向或管道时自动关闭，避免日志里混入 ANSI 转义序列。
func defaultColor() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false // 按 NO_COLOR 约定：只要设置了就禁用（取值不限）
	}
	st, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

func usage(w io.Writer) {
	fmt.Fprint(w, `scanner — Web 指纹识别、暴露面探测与 JS 敏感信息审计

用法:
  scanner -u <目标> [选项]            扫描单个目标
  scanner -l <文件> [选项]            批量扫描
  scanner update [--source-dir <目录>] 更新指纹库（从 GitHub 拉取 FingerprintHub 重新转换）

常用选项:
  -u, --url <目标>        域名 / IP / IP:端口 / 域名:端口 / 完整 URL
  -l, --list <文件>       目标列表文件（# 开头为注释，空行忽略）
      --both              两个协议都扫描
      --base-path <路径>  手动指定部署 base 路径（如 /oa）
      --rate <float>      单目标 QPS（默认取配置，5）
      --concurrency <n>   目标级并发（默认取配置，10）
      --timeout <dur>     单请求超时（默认 10s）
      --proxy <url>       代理（默认取配置或 HTTPS_PROXY）
      --out <目录>        报告输出目录（默认 reports）
      --json <路径>       JSON 报告路径（- 表示输出到标准输出）
      --html <路径>       HTML 报告路径
      --no-js             跳过 JS 审计
      --no-probe          跳过暴露面探测
      --no-semantic       不使用语义层
      --no-color          强制关闭彩色输出
      --quiet             不输出终端报告
      --verbose           输出更多细节
      --config <路径>     配置文件路径
      --version           打印版本
  -h, --help              显示本帮助

说明:
  · 默认跳过 TLS 证书校验（大量目标为自签证书或 IP 直连），--verify-tls 可开启
  · 只分析、绝不主动请求 JS 中发现的接口；探测只做判活，不发送任何 payload
  · 启用语义层时，目标站点的 JS 片段会发送给第三方 API，详见 README
`)
}
