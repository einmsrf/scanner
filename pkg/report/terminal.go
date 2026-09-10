package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/einmsrf/scanner/pkg/httpx"
)

// classDisplay 把失败大类翻译成中文说明。
func classDisplay(kind string) string {
	return httpx.ErrorClass(kind).Display()
}

// 终端 ANSI 颜色。高危用红底白字，保证在浅色/深色终端都醒目。
const (
	ansiReset   = "\x1b[0m"
	ansiBold    = "\x1b[1m"
	ansiDim     = "\x1b[2m"
	ansiRed     = "\x1b[31m"
	ansiGreen   = "\x1b[32m"
	ansiYellow  = "\x1b[33m"
	ansiBlue    = "\x1b[34m"
	ansiMagenta = "\x1b[35m"
	ansiCyan    = "\x1b[36m"
	ansiRedBG   = "\x1b[41;97m"
)

// TerminalOptions 控制终端输出。
type TerminalOptions struct {
	Color bool // 是否使用 ANSI 颜色（NO_COLOR 或非终端时由调用方置 false）
	// Verbose 为真时展示每个目标的请求明细与探测过的 URL。
	Verbose bool
}

// severityColor 返回级别对应的颜色码。
func severityColor(sev string) string {
	switch SeverityRank(sev) {
	case 0:
		return ansiRedBG // 严重：红底白字
	case 1:
		return ansiRed
	case 2:
		return ansiYellow
	case 3:
		return ansiCyan
	default:
		return ansiDim
	}
}

// WriteTerminal 输出人类可读的彩色摘要。
func (r *Report) WriteTerminal(w io.Writer, opts TerminalOptions) error {
	c := &colorizer{on: opts.Color}
	bw := &errWriter{w: w}

	// 头部
	bw.printf("%s%s scanner %s%s\n", c.wrap(ansiBold), r.Tool, r.Version, c.wrap(ansiReset))
	bw.printf("%s生成时间:%s %s\n", c.wrap(ansiDim), c.wrap(ansiReset), r.GeneratedAt)
	if r.Fingerprints != "" {
		bw.printf("%s指纹库:%s %s\n", c.wrap(ansiDim), c.wrap(ansiReset), r.Fingerprints)
	}
	if r.Semantic != "" {
		bw.printf("%s语义层:%s %s\n", c.wrap(ansiDim), c.wrap(ansiReset), r.Semantic)
	}
	bw.printf("\n")

	for _, t := range r.Targets {
		writeTarget(bw, c, t, opts)
	}

	writeSummary(bw, c, r)
	return bw.err
}

func writeTarget(bw *errWriter, c *colorizer, t *TargetReport, opts TerminalOptions) {
	bw.printf("%s%s── %s%s\n", c.wrap(ansiBold), c.wrap(ansiBlue), t.Target, c.wrap(ansiReset))

	if !t.OK() {
		kind := ""
		if t.FailureKind != "" {
			kind = " [" + t.FailureKind + "]"
		}
		bw.printf("  %s✗ 扫描失败%s:%s %s\n\n", c.wrap(ansiRed), kind, c.wrap(ansiReset), t.Error)
		return
	}
	// 暂停访问页的结果必然残缺，必须显眼提示，否则容易被误读成"目标没问题"
	if t.Suspended {
		bw.printf("  %s⚠ 目标暂停服务，结果不完整%s（%s）\n", c.wrap(ansiYellow), c.wrap(ansiReset), t.SuspendedReason)
	}
	status := fmt.Sprintf("HTTP %d", t.Status)
	if t.Status >= 400 {
		status = c.wrap(ansiYellow) + status + c.wrap(ansiReset)
	}
	line := fmt.Sprintf("  %s", status)
	if t.URL != "" && t.URL != t.Target {
		line += fmt.Sprintf("  %s%s%s", c.wrap(ansiDim), t.URL, c.wrap(ansiReset))
	}
	if t.Server != "" {
		line += fmt.Sprintf("  %sserver=%s%s", c.wrap(ansiDim), t.Server, c.wrap(ansiReset))
	}
	bw.printf("%s\n", line)
	if t.Title != "" {
		bw.printf("  标题: %s\n", t.Title)
	}
	if t.Duration != "" {
		bw.printf("  %s耗时 %s，请求 %d 次%s\n", c.wrap(ansiDim), t.Duration, t.Requests, c.wrap(ansiReset))
	}

	// 指纹
	if len(t.Fingerprints) > 0 {
		bw.printf("  %s指纹 (%d):%s\n", c.wrap(ansiBold), len(t.Fingerprints), c.wrap(ansiReset))
		for _, f := range t.Fingerprints {
			via := ""
			if f.Via != "" {
				via = fmt.Sprintf(" %s[%s]%s", c.wrap(ansiDim), viaDisplay(f.Via), c.wrap(ansiReset))
			}
			bw.printf("    · %s%s", f.Display(), via)
			if f.Evidence != "" {
				bw.printf("  %s%s%s", c.wrap(ansiDim), truncate(f.Evidence, 60), c.wrap(ansiReset))
			}
			bw.printf("\n")
		}
	}

	// 暴露面
	if len(t.Exposures) > 0 {
		bw.printf("  %s暴露面 (%d):%s\n", c.wrap(ansiBold), len(t.Exposures), c.wrap(ansiReset))
		for _, e := range t.Exposures {
			bw.printf("    %s[%s]%s %s  %s%s%s\n",
				c.wrap(severityColor(e.Severity)), SeverityDisplay(e.Severity), c.wrap(ansiReset),
				e.Name, c.wrap(ansiDim), e.Path, c.wrap(ansiReset))
			if e.Evidence != "" {
				bw.printf("          %s证据: %s%s\n", c.wrap(ansiDim), truncate(e.Evidence, 70), c.wrap(ansiReset))
			}
		}
	}

	// JS 审计
	if t.JS != nil && (len(t.JS.Findings) > 0 || len(t.JS.Endpoints) > 0) {
		js := t.JS
		bw.printf("  %sJS 审计:%s %d 个文件", c.wrap(ansiBold), c.wrap(ansiReset), js.AssetsScanned)
		if js.SourceMapHits > 0 {
			bw.printf("（其中 %d 个 sourcemap 还原）", js.SourceMapHits)
		}
		bw.printf("\n")

		if len(js.Findings) > 0 {
			bw.printf("    敏感信息 (%d):\n", len(js.Findings))
			for _, f := range js.Findings {
				bw.printf("      %s[%s]%s %s", c.wrap(severityColor(f.Severity)), SeverityDisplay(f.Severity), c.wrap(ansiReset), f.Category)
				loc := f.File
				if f.Line > 0 {
					loc = fmt.Sprintf("%s:%d", f.File, f.Line)
				}
				bw.printf("  %s%s%s\n", c.wrap(ansiDim), loc, c.wrap(ansiReset))
				if f.Decoded != "" {
					bw.printf("          %s解码: %s%s\n", c.wrap(ansiGreen), truncate(f.Decoded, 120), c.wrap(ansiReset))
				} else if f.Value != "" {
					bw.printf("          值: %s\n", truncate(f.Value, 120))
				}
				if f.Semantic != nil && f.Semantic.Judged {
					mark := "误报"
					col := ansiDim
					if f.Semantic.IsSensitive {
						mark, col = "确认敏感", ansiRed
					}
					bw.printf("          %s语义复核: %s（置信度 %.2f）%s %s\n",
						c.wrap(col), mark, f.Semantic.Confidence, c.wrap(ansiReset), truncate(f.Semantic.Reason, 80))
				}
			}
		}
		if len(js.Endpoints) > 0 {
			bw.printf("    接口路径 (%d, 仅展示不请求):\n", len(js.Endpoints))
			for i, e := range js.Endpoints {
				if i >= 20 {
					bw.printf("      %s… 其余 %d 条见 JSON/HTML 报告%s\n", c.wrap(ansiDim), len(js.Endpoints)-20, c.wrap(ansiReset))
					break
				}
				if e.Semantic != nil && e.Semantic.Judged && e.Semantic.IsSensitive {
					bw.printf("      %s[!]%s %s %s高危接口: %s%s\n",
						c.wrap(ansiRed), c.wrap(ansiReset), e.Path, c.wrap(ansiDim), truncate(e.Semantic.Reason, 60), c.wrap(ansiReset))
					continue
				}
				bw.printf("      %s%s%s\n", c.wrap(ansiDim), e.Path, c.wrap(ansiReset))
			}
		}
	}

	if opts.Verbose {
		for _, n := range t.Notes {
			bw.printf("  %s备注: %s%s\n", c.wrap(ansiDim), n, c.wrap(ansiReset))
		}
	}
	bw.printf("\n")
}

func writeSummary(bw *errWriter, c *colorizer, r *Report) {
	s := r.Summary
	bw.printf("%s%s── 汇总%s\n", c.wrap(ansiBold), c.wrap(ansiBlue), c.wrap(ansiReset))
	bw.printf("  目标 %d（成功 %d / 失败 %d），请求 %d 次，耗时 %s\n",
		s.Targets, s.TargetsOK, s.TargetsFailed, s.Requests, s.Duration)
	bw.printf("  指纹命中 %d，暴露面 %d，JS 敏感信息 %d，接口路径 %d\n",
		s.Fingerprints, s.Exposures, s.JSFindings, s.Endpoints)

	// 失败原因分布：帮助判断是"目标真死"还是"出口被丢包/限速"
	if len(s.FailureReasons) > 0 {
		keys := make([]string, 0, len(s.FailureReasons))
		for k := range s.FailureReasons {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s×%d", classDisplay(k), s.FailureReasons[k]))
		}
		bw.printf("  %s失败原因: %s%s\n", c.wrap(ansiDim), strings.Join(parts, "  "), c.wrap(ansiReset))
		// 超时占多数时给出可操作的提示
		if s.TargetsFailed > 0 && s.FailureReasons["timeout"]*10 >= s.TargetsFailed*6 {
			bw.printf("  %s提示: 超时占多数，多为出口被丢包或防护设备限速；可降低 --concurrency 或稍后重试%s\n",
				c.wrap(ansiDim), c.wrap(ansiReset))
		}
	}

	// 级别统计：有值的才显示，严重的排前面
	parts := []string{}
	for _, kv := range []struct {
		sev string
		n   int
	}{
		{string(SevCritical), s.Critical},
		{string(SevHigh), s.High},
		{string(SevMedium), s.Medium},
		{string(SevLow), s.Low},
		{string(SevInfo), s.Info},
	} {
		if kv.n == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s%s×%d%s",
			c.wrap(severityColor(kv.sev)), SeverityDisplay(kv.sev), kv.n, c.wrap(ansiReset)))
	}
	if len(parts) > 0 {
		bw.printf("  级别统计: %s\n", strings.Join(parts, "  "))
	} else {
		bw.printf("  %s未发现风险项%s\n", c.wrap(ansiGreen), c.wrap(ansiReset))
	}
}

// colorizer 在关闭颜色时返回空串，保证 NO_COLOR/重定向场景无 ANSI 噪声。
type colorizer struct{ on bool }

func (c *colorizer) wrap(code string) string {
	if !c.on {
		return ""
	}
	return code
}

// viaDisplay 把命中方式转成中文。
func viaDisplay(via string) string {
	switch via {
	case "landing":
		return "落地页"
	case "path":
		return "路径探测"
	case "subdir":
		return "子目录候选"
	case "favicon":
		return "favicon"
	default:
		return via
	}
}

// truncate 截断过长文本，并保证返回合法 UTF-8。
func truncate(s string, n int) string {
	r := []rune(strings.Join(strings.Fields(s), " "))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

// errWriter 记住首个写错误，避免每处都判错。
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}
