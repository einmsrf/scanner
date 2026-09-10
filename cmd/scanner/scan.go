package main

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	scanner "github.com/einmsrf/scanner"
	"github.com/einmsrf/scanner/pkg/config"
	"github.com/einmsrf/scanner/pkg/fingerprint"
	"github.com/einmsrf/scanner/pkg/httpx"
	"github.com/einmsrf/scanner/pkg/jsaudit"
	"github.com/einmsrf/scanner/pkg/probe"
	"github.com/einmsrf/scanner/pkg/report"
	"github.com/einmsrf/scanner/pkg/semantic"
	"github.com/einmsrf/scanner/pkg/target"
)

// toolName / toolVersion 供报告与 --version 使用。
const (
	toolName    = "scanner"
	toolVersion = scanner.Version
)

// app 持有各层引擎，便于在多个目标间复用。
type app struct {
	cfg  config.Config
	opts options

	fpEngine  *fingerprint.Engine
	fpSource  string
	probeLib  *probe.Library
	semClient *semantic.Client
	semStatus string

	stdout io.Writer
	stderr io.Writer
}

// newApp 装配各层：指纹库、探测规则库、语义层客户端。
func newApp(cfg config.Config, o options, stdout, stderr io.Writer) (*app, error) {
	a := &app{cfg: cfg, opts: o, stdout: stdout, stderr: stderr}

	// 指纹库：磁盘 fingerprints.json 优先（scanner update 后可免重编译生效）
	lib, src, err := fingerprint.Load(scanner.FingerprintsJSON)
	if err != nil {
		if o.strictFP {
			return nil, err
		}
		return nil, fmt.Errorf("加载指纹库失败: %w", err)
	}
	a.fpEngine = fingerprint.NewEngine(lib)
	a.fpSource = src

	// 探测规则库
	pLib, err := probe.Load(scanner.ProbePacksYAML, scanner.ExposureYAML)
	if err != nil {
		// 个别探测项无效不应阻断扫描，但要让使用者知道
		fmt.Fprintf(stderr, "警告: %v\n", err)
	}
	if pLib == nil {
		return nil, fmt.Errorf("加载探测规则失败: %w", err)
	}
	a.probeLib = pLib

	// 语义层（可降级）
	switch {
	case o.noSemants:
		a.semStatus = "已按 --no-semantic 关闭"
	case !cfg.SemanticEnabled():
		a.semStatus = "未配置 api_key，已降级为纯正则模式"
	default:
		cli, serr := semantic.New(semantic.Options{
			BaseURL: cfg.LLM.BaseURL,
			APIKey:  cfg.LLM.APIKey,
			Model:   cfg.LLM.Model,
			Timeout: cfg.LLM.Timeout.Std(),
			Proxy:   cfg.Proxy,
		})
		if serr != nil {
			// 静默降级：不中断扫描
			a.semStatus = "不可用，已降级为纯正则模式（" + serr.Error() + "）"
		} else {
			a.semClient = cli
			a.semStatus = fmt.Sprintf("已启用（%s @ %s）", cfg.LLM.Model, cfg.LLM.BaseURL)
		}
	}
	return a, nil
}

func (a *app) close() {
	if a.semClient != nil {
		a.semClient.Close()
	}
}

// collectTargets 汇总 -u 与 -l 的目标。
func collectTargets(url, listFile string) ([]target.Target, []string, error) {
	var (
		targets []target.Target
		bad     []string
	)
	seen := map[string]bool{}
	add := func(ts []target.Target) {
		for _, t := range ts {
			if k := t.Key(); !seen[k] {
				seen[k] = true
				targets = append(targets, t)
			}
		}
	}

	if strings.TrimSpace(url) != "" {
		t, err := target.Parse(url)
		if err != nil {
			return nil, nil, fmt.Errorf("解析目标 %q 失败: %w", url, err)
		}
		add([]target.Target{t})
	}
	if strings.TrimSpace(listFile) != "" {
		ts, b, err := target.LoadFile(listFile)
		if err != nil {
			return nil, nil, fmt.Errorf("读取目标文件失败: %w", err)
		}
		add(ts)
		bad = append(bad, b...)
	}
	return targets, bad, nil
}

// run 执行全部目标的扫描并输出报告。
func (a *app) run(stdout, stderr io.Writer) int {
	targets, _, err := collectTargets(a.opts.url, a.opts.targetsFile)
	if err != nil {
		fmt.Fprintf(stderr, "错误: %v\n", err)
		return 1
	}

	start := time.Now()
	results := make([]*report.TargetReport, len(targets))

	// 目标级并发（DESIGN.md 第 9 节）
	sem := make(chan struct{}, a.cfg.Scan.Concurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(idx int, tg target.Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = a.scanTarget(context.Background(), tg)
		}(i, t)
	}
	wg.Wait()

	rep := report.New(toolName, toolVersion)
	rep.Fingerprints = a.fpSource
	rep.Semantic = a.semStatus
	rep.Args = a.argsSummary()
	rep.Targets = results
	rep.Finalize(time.Since(start))

	// 终端
	if !a.opts.quiet && a.opts.jsonPath != "-" {
		if err := rep.WriteTerminal(stdout, report.TerminalOptions{Color: a.opts.color, Verbose: a.opts.verbose}); err != nil {
			fmt.Fprintf(stderr, "错误: 输出终端报告失败: %v\n", err)
			return 1
		}
	}

	// JSON / HTML
	jsonPath, htmlPath := a.outputPaths()
	if jsonPath == "-" {
		if err := rep.WriteJSON(stdout); err != nil {
			fmt.Fprintf(stderr, "错误: 输出 JSON 失败: %v\n", err)
			return 1
		}
		htmlPath = "" // 管道模式下不写文件
	} else if jsonPath != "" {
		if err := rep.WriteJSONFile(jsonPath); err != nil {
			fmt.Fprintf(stderr, "错误: 写入 JSON 报告失败: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "\nJSON 报告: %s\n", jsonPath)
	}
	if htmlPath != "" {
		if err := rep.WriteHTMLFile(htmlPath); err != nil {
			fmt.Fprintf(stderr, "错误: 写入 HTML 报告失败: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "HTML 报告: %s\n", htmlPath)
	}
	return 0
}

// argsSummary 记录命令行摘要，便于报告复现。
func (a *app) argsSummary() string {
	parts := []string{toolName}
	if a.opts.url != "" {
		parts = append(parts, "-u", a.opts.url)
	}
	if a.opts.targetsFile != "" {
		parts = append(parts, "-l", a.opts.targetsFile)
	}
	if a.opts.both {
		parts = append(parts, "--both")
	}
	if a.opts.basePath != "" {
		parts = append(parts, "--base-path", a.opts.basePath)
	}
	if a.opts.configPath != "" {
		parts = append(parts, "--config", a.opts.configPath)
	}
	if a.opts.noJS {
		parts = append(parts, "--no-js")
	}
	if a.opts.noProbe {
		parts = append(parts, "--no-probe")
	}
	return strings.Join(parts, " ")
}

// outputPaths 决定 JSON / HTML 的输出路径。时间戳命名避免覆盖历史结果。
func (a *app) outputPaths() (jsonPath, htmlPath string) {
	if a.opts.jsonPath == "-" {
		return "-", ""
	}
	outDir := a.opts.outDir
	if outDir == "" {
		outDir = defaultOutDir
	}
	stamp := time.Now().Format("20060102-150405")
	jsonPath = a.opts.jsonPath
	if jsonPath == "" {
		jsonPath = filepath.Join(outDir, "scan-"+stamp+".json")
	}
	htmlPath = a.opts.htmlPath
	if htmlPath == "" {
		htmlPath = filepath.Join(outDir, "scan-"+stamp+".html")
	}
	return jsonPath, htmlPath
}

// scanTarget 扫描单个目标：协议探测 → 指纹 → 暴露面 → JS 审计（→ 语义层）。
func (a *app) scanTarget(ctx context.Context, tg target.Target) *report.TargetReport {
	ctx, cancel := context.WithTimeout(ctx, a.opts.targetLimit)
	defer cancel()

	tr := &report.TargetReport{Target: tg.Raw}
	start := time.Now()
	defer func() { tr.Duration = time.Since(start).Round(time.Millisecond).String() }()

	client, err := httpx.New(httpx.Options{
		Timeout:       a.opts.timeout,
		QPS:           a.opts.rate,
		Proxy:         a.opts.proxy,
		MaxRequests:   a.opts.maxRequests,
		VerifyTLSFlag: a.opts.verifyTLS,
	})
	if err != nil {
		tr.Error = err.Error()
		return tr
	}
	defer client.Close()

	// 协议探测。只对瞬时错误（超时/连接被切断）重试——refused / DNS 失败
	// 重试没有意义，见 DESIGN.md 第 9 节实战修订。
	var (
		sites    []*target.Site
		probeErr error
	)
	for attempt := 0; ; attempt++ {
		sites, probeErr = target.Probe(ctx, client, tg, a.opts.both)
		if probeErr == nil || attempt >= a.opts.retry {
			break
		}
		class := httpx.ClassifyError(probeErr)
		if !class.Retryable() || client.Remaining() <= 0 {
			break
		}
		backoff := retryBackoff(attempt)
		if !sleepCtx(ctx, backoff) {
			break // 上下文已取消/超时
		}
		a.noteRetry(tg, attempt+1, class)
	}
	if probeErr != nil {
		tr.Error = probeErr.Error()
		tr.FailureKind = string(httpx.ClassifyError(probeErr))
		tr.Requests = client.Used()
		return tr
	}

	merged := false
	for _, site := range sites {
		sr := a.scanSite(ctx, client, site)
		if !merged {
			*tr = *sr
			merged = true
			continue
		}
		mergeTargets(tr, sr)
	}
	if !merged {
		tr.Error = "没有可用协议"
	}
	tr.Requests = client.Used()
	return tr
}

// scanSite 对单个「协议 + 站点」执行指纹、暴露面与 JS 审计。
func (a *app) scanSite(ctx context.Context, client *httpx.Client, site *target.Site) *report.TargetReport {
	tr := &report.TargetReport{
		Target: site.Target.Raw,
		URL:    site.LandingURL,
		Scheme: site.Scheme,
		Status: site.Landing.Status,
		Server: site.Landing.HeaderGet("Server"),
		Title:  report.ExtractTitle(site.Landing.Body),
	}
	if site.RootLanding != nil {
		tr.Notes = append(tr.Notes, fmt.Sprintf("base-path %s 未命中（HTTP %d），已回退站点根 %s",
			site.BasePath, site.Landing.Status, site.RootLanding.URL))
	}

	// 暂停访问页识别：这类页面的结果必然残缺，必须显著标注
	if info := target.DetectSuspended(site.Landing); info.Suspended {
		tr.Suspended = true
		tr.SuspendedReason = info.Reason
		tr.Notes = append(tr.Notes, "目标疑似暂停服务（"+info.Reason+"），本次结果不完整")
	}

	// 1) 先做 JS 审计：它只依赖已抓取的落地页，且能反哺候选 base。
	//    顺序调整的背景见 DESIGN.md 第 5.2 节实战修订。
	var jsRes *jsaudit.Report
	if !a.opts.noJS {
		jsRes = jsaudit.Run(ctx, client, site.Origin, site.Responses(), jsaudit.DefaultRunOptions())
	}

	// 2) 候选 base = 落地页推出的 + JS 接口前缀反哺的（应对 nginx 反代前缀场景）
	bases := site.CandidateBases()
	if jsRes != nil {
		if extra := jsRes.BasePrefixCandidates(maxPrefixBases); len(extra) > 0 {
			bases = appendUniqueBases(bases, extra)
			tr.Notes = append(tr.Notes, fmt.Sprintf("由 JS 接口前缀补充候选 base: %s", strings.Join(extra, " ")))
		}
	}

	// 3) 指纹（四层兜底）
	var fpMatches []fingerprint.Match
	fpRes, err := a.fpEngine.Scan(ctx, client, fingerprint.Input{
		Origin:         site.Origin,
		Root:           site.RootResponse(),
		Pages:          site.Responses(),
		BasePaths:      bases,
		ManualBasePath: a.opts.basePath,
	}, fingerprint.Options{})
	if err != nil {
		tr.Notes = append(tr.Notes, "指纹识别失败: "+err.Error())
	} else {
		fpMatches = fpRes.Matches
		tr.Fingerprints = report.FromFingerprintMatches(fpRes.Matches)
		tr.Notes = append(tr.Notes, fpRes.Notes...)
	}

	// 4) 暴露面探测（先取 404 基线过滤软 404）
	if !a.opts.noProbe {
		var baseline *httpx.Baseline
		if bl, berr := client.FetchBaselineAt(ctx, site.Origin); berr != nil {
			tr.Notes = append(tr.Notes, "404 基线获取失败，误报率可能升高: "+berr.Error())
		} else {
			baseline = bl
		}
		pr := probe.New(a.probeLib)
		pRes := pr.Run(ctx, client, site.Origin, fpMatches, baseline, probe.Options{
			Bases: bases,
		})
		tr.Exposures = report.FromProbeFindings(pRes.Findings)
		tr.Notes = append(tr.Notes, pRes.Notes...)
	}

	// 5) 收尾 JS 结果（含语义层）
	if jsRes != nil {
		var verdicts report.VerdictFunc
		if a.semClient != nil {
			verdicts = a.scoreSemantic(ctx, jsRes, tr)
		}
		tr.JS = report.FromJSAudit(jsRes, verdicts)
		tr.Notes = append(tr.Notes, jsRes.Notes...)
	}
	return tr
}

// scoreSemantic 把 JS 可疑片段与接口路径送语义层打分，返回查询函数。
func (a *app) scoreSemantic(ctx context.Context, jsRes *jsaudit.Report, tr *report.TargetReport) report.VerdictFunc {
	snippets := jsRes.Snippets()
	items := make([]semantic.Item, 0, len(snippets)+len(jsRes.Endpoints))
	for _, s := range snippets {
		items = append(items, semantic.Item{ID: s.ID, Text: s.Text, Kind: semantic.KindSnippet})
	}
	for _, e := range jsRes.Endpoints {
		items = append(items, semantic.Item{ID: report.EndpointID(e.Path), Text: e.Path, Kind: semantic.KindEndpoint})
	}
	if len(items) == 0 {
		return nil
	}

	verdicts, err := a.semClient.Score(ctx, items)
	if err != nil {
		// 静默降级：只记一条备注，发现仍按纯正则结论展示
		tr.Notes = append(tr.Notes, "语义层调用失败，已降级为纯正则结果: "+err.Error())
	}
	byID := make(map[string]*report.SemanticNote, len(verdicts))
	for _, v := range verdicts {
		if !v.Judged {
			continue
		}
		byID[v.ID] = &report.SemanticNote{
			Judged:      true,
			IsSensitive: v.IsSensitive,
			Reason:      v.Reason,
			Confidence:  v.Confidence,
		}
	}
	if len(byID) == 0 {
		return nil
	}
	return func(id string) *report.SemanticNote { return byID[id] }
}

// mergeTargets 把两个站点（--both 时的 http/https）的结果合并到一个目标报告里。
func mergeTargets(dst, src *report.TargetReport) {
	if dst.URL == "" {
		dst.URL = src.URL
	}
	if src.URL != "" && src.URL != dst.URL {
		dst.Notes = append(dst.Notes, "另一协议结果已合并: "+src.URL)
	}

	seenFP := map[string]bool{}
	for _, f := range dst.Fingerprints {
		seenFP[f.ID] = true
	}
	for _, f := range src.Fingerprints {
		if !seenFP[f.ID] {
			seenFP[f.ID] = true
			dst.Fingerprints = append(dst.Fingerprints, f)
		}
	}

	seenEx := map[string]bool{}
	for _, e := range dst.Exposures {
		seenEx[e.Family+"|"+e.Path] = true
	}
	for _, e := range src.Exposures {
		if k := e.Family + "|" + e.Path; !seenEx[k] {
			seenEx[k] = true
			dst.Exposures = append(dst.Exposures, e)
		}
	}

	dst.JS = mergeJS(dst.JS, src.JS)
	if src.Server != "" && dst.Server == "" {
		dst.Server = src.Server
	}
	dst.Notes = append(dst.Notes, src.Notes...)
}

// mergeJS 合并两段 JS 审计结果。
func mergeJS(dst, src *report.JSSection) *report.JSSection {
	if src == nil {
		return dst
	}
	if dst == nil {
		return src
	}
	dst.AssetsScanned += src.AssetsScanned
	dst.SourceMapHits += src.SourceMapHits

	seenPage := map[string]bool{}
	for _, p := range dst.Pages {
		seenPage[p] = true
	}
	for _, p := range src.Pages {
		if !seenPage[p] {
			seenPage[p] = true
			dst.Pages = append(dst.Pages, p)
		}
	}

	seenF := map[string]bool{}
	for _, f := range dst.Findings {
		seenF[f.CategoryKey+"|"+f.File+"|"+f.Value] = true
	}
	for _, f := range src.Findings {
		if k := f.CategoryKey + "|" + f.File + "|" + f.Value; !seenF[k] {
			seenF[k] = true
			dst.Findings = append(dst.Findings, f)
		}
	}

	epIdx := map[string]int{}
	for i, e := range dst.Endpoints {
		epIdx[e.Path] = i
	}
	for _, e := range src.Endpoints {
		if i, ok := epIdx[e.Path]; ok {
			dst.Endpoints[i].Count += e.Count
			if dst.Endpoints[i].Semantic == nil {
				dst.Endpoints[i].Semantic = e.Semantic
			}
			continue
		}
		epIdx[e.Path] = len(dst.Endpoints)
		dst.Endpoints = append(dst.Endpoints, e)
	}

	dst.Notes = append(dst.Notes, src.Notes...)
	return dst
}

// maxPrefixBases 是由 JS 接口前缀反哺的候选 base 数量上限。
// 取 3 是为了在"覆盖反代前缀"与"不浪费请求预算"之间取平衡（DESIGN.md 第 5.2 节）。
const maxPrefixBases = 3

// appendUniqueBases 把 extra 里尚不存在的 base 追加到 bases。
// 顺序保持"已有候选优先"，因此不会挤掉落地页推出的高优先级候选。
func appendUniqueBases(bases, extra []string) []string {
	seen := map[string]bool{}
	for _, b := range bases {
		seen[b] = true
	}
	for _, b := range extra {
		if b == "" || seen[b] {
			continue
		}
		seen[b] = true
		bases = append(bases, b)
	}
	return bases
}

// retryBackoff 返回第 attempt 次重试前的等待时长（指数退避，上限 2s）。
func retryBackoff(attempt int) time.Duration {
	d := 300 * time.Millisecond << uint(attempt)
	if d > 2*time.Second {
		d = 2 * time.Second
	}
	return d
}

// sleepCtx 等待 d，若上下文先结束则返回 false。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// noteRetry 在 stderr 打印一行重试提示（保持输出简洁，不逐目标刷屏过多）。
func (a *app) noteRetry(tg target.Target, attempt int, class httpx.ErrorClass) {
	fmt.Fprintf(a.stderr, "重试 %s（第 %d 次，原因 %s：%s）\n", tg.Raw, attempt, class, class.Display())
}
