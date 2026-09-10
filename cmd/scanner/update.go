package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/einmsrf/scanner/pkg/config"
	"github.com/einmsrf/scanner/pkg/convert"
	"github.com/einmsrf/scanner/pkg/fingerprint"
	"github.com/einmsrf/scanner/pkg/httpx"
)

// FingerprintHub 上游信息。
const (
	fingerprintHubRepo    = "0x727/FingerprintHub"
	defaultBranch         = "main"
	defaultFingerprintOut = "fingerprints.json"
	maxZipBytes           = 256 << 20 // 上游压缩包约数十 MB，留足余量
)

// updateResult 汇总一次转换的结果。
type updateResult struct {
	Lib    *fingerprint.Library
	Stats  *convert.Stats
	Source string
}

// runUpdate 实现 `scanner update`：把 FingerprintHub 的 nuclei 模板重新转换成
// scanner 内部的指纹库 JSON。
//
// 两种来源：
//   - 默认从 GitHub 下载 zip 并在**内存中**转换（不落盘解包，避开 Windows 上的
//     中文文件名与长路径问题）
//   - --source-dir 指定本地已解包的模板目录，便于离线更新或锁定 commit
//
// 产出的 fingerprints.json 会被运行时优先于内置版本加载（见 fingerprint.Load），
// 因此更新后无需重新编译即可生效。
func runUpdate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scanner update", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		sourceDir  string
		out        string
		proxy      string
		branch     string
		timeout    time.Duration
		dryRun     bool
		configPath string
	)
	fs.StringVar(&sourceDir, "source-dir", "", "本地模板目录（离线转换，优先于网络下载）")
	fs.StringVar(&out, "out", defaultFingerprintOut, "输出的指纹库路径")
	fs.StringVar(&proxy, "proxy", "", "代理地址（覆盖配置文件）")
	fs.StringVar(&branch, "branch", defaultBranch, "GitHub 分支名")
	fs.DurationVar(&timeout, "timeout", 2*time.Minute, "下载与转换超时")
	fs.BoolVar(&dryRun, "dry-run", false, "只转换并打印统计，不写文件")
	fs.StringVar(&configPath, "config", "", "配置文件路径")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "错误: %v\n", err)
		return 1
	}
	if proxy == "" {
		proxy = cfg.Proxy
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	res, err := buildLibrary(ctx, sourceDir, proxy, branch, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "错误: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "来源: %s\n", res.Source)
	fmt.Fprintf(stdout, "转换: %s\n", res.Stats)
	for _, e := range res.Stats.Errors {
		fmt.Fprintf(stderr, "  解析失败: %s\n", e)
	}

	if dryRun {
		fmt.Fprintln(stdout, "（--dry-run：未写入文件）")
		return 0
	}

	data, err := convert.MarshalLibrary(res.Lib)
	if err != nil {
		fmt.Fprintf(stderr, "错误: 序列化失败: %v\n", err)
		return 1
	}
	if dir := filepath.Dir(out); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(stderr, "错误: 创建目录失败: %v\n", err)
			return 1
		}
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		fmt.Fprintf(stderr, "错误: 写入 %s 失败: %v\n", out, err)
		return 1
	}
	fmt.Fprintf(stdout, "已写入 %s（%d 条规则，%d 字节）\n", out, res.Lib.Count, len(data))
	fmt.Fprintln(stdout, "下次扫描会优先加载该文件，无需重新编译。")
	return 0
}

// buildLibrary 从本地目录或 GitHub 得到转换后的指纹库。
func buildLibrary(ctx context.Context, sourceDir, proxy, branch string, stderr io.Writer) (*updateResult, error) {
	if sourceDir != "" {
		dir, err := resolveTemplateDir(sourceDir)
		if err != nil {
			return nil, err
		}
		source := "local:" + dir
		if abs, aerr := filepath.Abs(dir); aerr == nil {
			source = "local:" + abs
		}
		lib, stats, err := convert.ConvertDir(dir, source)
		if err != nil {
			return nil, fmt.Errorf("转换失败: %w", err)
		}
		return &updateResult{Lib: lib, Stats: stats, Source: source}, nil
	}
	return downloadAndConvert(ctx, proxy, branch, stderr)
}

// resolveTemplateDir 定位模板目录：若给定目录下存在 web-fingerprint 子目录则进入它。
func resolveTemplateDir(dir string) (string, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("模板目录不可用: %w", err)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%s 不是目录", dir)
	}
	sub := filepath.Join(dir, convert.DefaultTemplateDir)
	if s, err := os.Stat(sub); err == nil && s.IsDir() {
		return sub, nil
	}
	return dir, nil
}

// downloadAndConvert 从 GitHub 下载仓库 zip 并在内存中转换。
func downloadAndConvert(ctx context.Context, proxy, branch string, stderr io.Writer) (*updateResult, error) {
	client, err := httpx.New(httpx.Options{
		Timeout:     60 * time.Second,
		QPS:         -1,
		Proxy:       proxy,
		MaxBody:     maxZipBytes,
		MaxRequests: 10,
	})
	if err != nil {
		return nil, err
	}
	defer client.Close()

	// 尽力解析当前 commit，让产物里的来源可追溯（失败不影响主流程）
	ref := branch
	if sha := resolveHeadSHA(ctx, client, branch); sha != "" {
		ref = sha
	}
	source := fmt.Sprintf("github.com/%s@%s", fingerprintHubRepo, ref)

	zipURL := fmt.Sprintf("https://codeload.github.com/%s/zip/refs/heads/%s", fingerprintHubRepo, branch)
	fmt.Fprintf(stderr, "正在下载 %s …\n", zipURL)
	resp, err := client.Get(ctx, zipURL)
	if err != nil {
		return nil, fmt.Errorf("下载失败（网络不通可试 --proxy http://127.0.0.1:7890）: %w", err)
	}
	if resp.Status >= 400 {
		return nil, fmt.Errorf("下载失败: HTTP %d", resp.Status)
	}
	if resp.Truncated {
		return nil, fmt.Errorf("下载内容超过 %d 字节上限，已中止", maxZipBytes)
	}

	zr, err := zip.NewReader(bytes.NewReader(resp.Body), int64(len(resp.Body)))
	if err != nil {
		return nil, fmt.Errorf("解析 zip 失败: %w", err)
	}
	root, err := findTemplateRoot(zr)
	if err != nil {
		return nil, err
	}
	lib, stats, err := convert.ConvertFS(root, source)
	if err != nil {
		return nil, fmt.Errorf("转换失败: %w", err)
	}
	return &updateResult{Lib: lib, Stats: stats, Source: source}, nil
}

// findTemplateRoot 在 zip 里定位 web-fingerprint 目录。
// GitHub 的 zip 顶层是 <repo>-<branch>/，故先下钻一层。
func findTemplateRoot(zr *zip.Reader) (fs.FS, error) {
	entries, err := fs.ReadDir(zr, ".")
	if err != nil {
		return nil, fmt.Errorf("读取 zip 根目录失败: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cand := e.Name() + "/" + convert.DefaultTemplateDir
		if st, err := fs.Stat(zr, cand); err == nil && st.IsDir() {
			return fs.Sub(zr, cand)
		}
	}
	// 退化情形：zip 内容本身就是模板目录
	return zr, nil
}

// resolveHeadSHA 通过 GitHub API 取分支头 commit；失败返回空串。
func resolveHeadSHA(ctx context.Context, client *httpx.Client, branch string) string {
	u := fmt.Sprintf("https://api.github.com/repos/%s/commits/%s", fingerprintHubRepo, branch)
	resp, err := client.Get(ctx, u)
	if err != nil || resp.Status >= 400 {
		return ""
	}
	var v struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(resp.Body, &v); err != nil {
		return ""
	}
	if len(v.SHA) > 12 {
		return v.SHA[:12]
	}
	return v.SHA
}
