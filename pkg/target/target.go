// Package target 负责把用户输入的一行文本解析成可探测的目标，
// 并按协议策略（https 优先、失败降级 http）完成协议探测与落地页获取。
//
// 支持的输入形式见 DESIGN.md 第 3 节：
//
//	example.com              域名
//	1.2.3.4                  IP
//	1.2.3.4:8080             IP:端口
//	example.com:8443         域名:端口
//	https://example.com/app  完整 URL（路径作为 base-path 提示）
//	# 注释行 / 空行           忽略
package target

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/einmsrf/scanner/pkg/httpx"
)

// ErrEmpty 表示该行是空行或注释，应被忽略。
var ErrEmpty = errors.New("target: 空行或注释")

// Target 是一个解析后的目标。
type Target struct {
	Raw      string // 原始输入行（去空白）
	Host     string // 主机名或 IP（不含端口、不含方括号）
	Port     int    // 显式端口；0 表示未指定
	Scheme   string // 显式协议（http/https）；空表示未指定
	BasePath string // URL 中的路径提示，恒以 / 开头或为空
	hasPort  bool
}

// Key 返回用于去重的稳定标识。
func (t Target) Key() string {
	return fmt.Sprintf("%s|%d|%s|%s", strings.ToLower(t.Host), t.Port, t.Scheme, t.BasePath)
}

// String 便于日志输出。
func (t Target) String() string {
	if t.hasPort && t.Port > 0 {
		return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) + t.BasePath
	}
	return t.Host + t.BasePath
}

// IsIP 判断主机是否为 IP 字面量。
func (t Target) IsIP() bool { return net.ParseIP(t.Host) != nil }

// defaultPort 返回协议默认端口。
func defaultPort(scheme string) int {
	if scheme == "http" {
		return 80
	}
	return 443
}

// hostPort 返回 host[:port]，默认端口省略不写。
func (t Target) hostPort(scheme string) string {
	host := t.Host
	if strings.Contains(host, ":") { // IPv6 字面量需要方括号
		host = "[" + host + "]"
	}
	switch {
	case !t.hasPort || t.Port == 0:
		return host
	case t.Port == defaultPort(scheme):
		return host
	default:
		return host + ":" + strconv.Itoa(t.Port)
	}
}

// URLFor 返回指定协议下的探测 URL（含 base-path 提示）。
func (t Target) URLFor(scheme string) string {
	return scheme + "://" + t.hostPort(scheme) + t.BasePath
}

// OriginFor 返回指定协议下的站点根（不含路径）。
func (t Target) OriginFor(scheme string) string {
	return scheme + "://" + t.hostPort(scheme)
}

// PreferredSchemes 返回协议尝试顺序。
//
//	未指定协议：https 优先，http 兜底
//	指定了协议：优先该协议；both 为真时另一协议也一并尝试
func (t Target) PreferredSchemes(both bool) []string {
	switch t.Scheme {
	case "http", "https":
		other := "http"
		if t.Scheme == "http" {
			other = "https"
		}
		if both {
			return []string{t.Scheme, other}
		}
		return []string{t.Scheme}
	default:
		return []string{"https", "http"}
	}
}

// Parse 解析一行输入。空行与注释行返回 ErrEmpty。
func Parse(line string) (Target, error) {
	raw := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "\ufeff"))
	if raw == "" || strings.HasPrefix(raw, "#") {
		return Target{}, ErrEmpty
	}

	rest := raw
	scheme := ""
	if i := strings.Index(rest, "://"); i >= 0 {
		scheme = strings.ToLower(strings.TrimSpace(rest[:i]))
		if scheme != "http" && scheme != "https" {
			return Target{}, fmt.Errorf("target: 不支持的协议 %q（仅 http/https）", scheme)
		}
		rest = rest[i+3:]
	}

	// 去掉 userinfo（user:pass@host）
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest = rest[i+1:]
	}

	// 切出路径（含 query 的部分一并丢弃，路径提示只用路径）
	basePath := ""
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		p := rest[i:]
		rest = rest[:i]
		if strings.HasPrefix(p, "/") {
			basePath = p
			if j := strings.IndexByte(basePath, '?'); j >= 0 {
				basePath = basePath[:j]
			}
			if j := strings.IndexByte(basePath, '#'); j >= 0 {
				basePath = basePath[:j]
			}
			basePath = strings.TrimSuffix(basePath, "/")
		}
	}
	if rest == "" {
		return Target{}, fmt.Errorf("target: %q 缺少主机名", raw)
	}

	host, port, hasPort, err := splitHostPort(rest)
	if err != nil {
		return Target{}, fmt.Errorf("target: %q %w", raw, err)
	}
	if host == "" {
		return Target{}, fmt.Errorf("target: %q 缺少主机名", raw)
	}

	return Target{
		Raw:      raw,
		Host:     host,
		Port:     port,
		Scheme:   scheme,
		BasePath: basePath,
		hasPort:  hasPort,
	}, nil
}

// splitHostPort 解析 host[:port]，支持 IPv6 字面量（[::1]:8080 或 ::1）。
func splitHostPort(s string) (host string, port int, hasPort bool, err error) {
	// [IPv6]:port 或 [IPv6]
	if strings.HasPrefix(s, "[") {
		if !strings.Contains(s, "]") {
			return "", 0, false, errors.New("IPv6 地址缺少 ]")
		}
		h, p, e := net.SplitHostPort(s)
		if e == nil {
			pv, pe := parsePort(p)
			if pe != nil {
				return "", 0, false, pe
			}
			return h, pv, true, nil
		}
		// 没有端口的 [IPv6]
		return strings.Trim(s, "[]"), 0, false, nil
	}

	// 裸 IPv6（多个冒号且无端口）
	if strings.Count(s, ":") > 1 {
		if net.ParseIP(s) == nil {
			return "", 0, false, errors.New("IPv6 地址格式错误")
		}
		return s, 0, false, nil
	}

	if strings.Count(s, ":") == 1 {
		h, p, e := net.SplitHostPort(s)
		if e != nil {
			// 形如 example.com: 的残缺输入
			return "", 0, false, errors.New("端口格式错误")
		}
		pv, pe := parsePort(p)
		if pe != nil {
			return "", 0, false, pe
		}
		return h, pv, true, nil
	}
	return s, 0, false, nil
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("端口 %q 无效", s)
	}
	return n, nil
}

// ParseAll 从 r 读取目标列表，忽略空行与注释行，并按 Key 去重。
// 返回被忽略的非法行（含原因），供 CLI 提示用户。
func ParseAll(r io.Reader) (targets []Target, bad []string, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	seen := make(map[string]bool)
	for sc.Scan() {
		t, perr := Parse(sc.Text())
		if perr != nil {
			if errors.Is(perr, ErrEmpty) {
				continue
			}
			bad = append(bad, perr.Error())
			continue
		}
		if k := t.Key(); !seen[k] {
			seen[k] = true
			targets = append(targets, t)
		}
	}
	if e := sc.Err(); e != nil {
		return nil, bad, e
	}
	return targets, bad, nil
}

// LoadFile 读取目标列表文件。路径由调用方保证在项目目录内。
func LoadFile(path string) ([]Target, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	return ParseAll(f)
}

// Site 是一个已探活的目标站点（某个协议 + 落地页）。
type Site struct {
	Target   Target
	Scheme   string
	Origin   string // scheme://host[:port]，后续探测以此为根
	BasePath string // 本次实际请求的 base-path（"" 表示根）

	RequestedURL string
	Landing      *httpx.Response // 主落地页（已跟随重定向）
	LandingURL   string          // 落地页最终 URL
	LandingPath  string          // 落地页最终 URL 的路径部分

	// RootLanding 仅在 BasePath 非空且主请求未成功（>=400）时补取根路径，
	// 用于应对“路径提示失效但站点根可用”的情况。
	RootLanding *httpx.Response
}

// Responses 返回可参与指纹匹配的落地页响应（主落地页优先，根路径兜底次之）。
func (s *Site) Responses() []*httpx.Response {
	out := []*httpx.Response{}
	if s.Landing != nil {
		out = append(out, s.Landing)
	}
	if s.RootLanding != nil {
		out = append(out, s.RootLanding)
	}
	return out
}

// RootResponse 返回“请求站点根 origin/ 得到”的响应；未知时返回 nil。
// 指纹引擎的路径无关规则与 favicon 均以它为准（DESIGN.md 第 5.2 节第 1 层）。
func (s *Site) RootResponse() *httpx.Response {
	if s.BasePath == "" {
		return s.Landing
	}
	return s.RootLanding
}

// CandidateBases 返回路径型规则可尝试的 base 前缀（按优先级去重）：
// 落地页所在目录 → 请求的 base-path → 站点根。
// 这是 DESIGN.md 第 5.2 节第 1、4 层兜底的基础。
func (s *Site) CandidateBases() []string {
	var cands []string
	add := func(p string) {
		p = strings.TrimSuffix(p, "/")
		if p == "" {
			p = "/"
		}
		for _, c := range cands {
			if c == p {
				return
			}
		}
		cands = append(cands, p)
	}
	if dir := dirOf(s.LandingPath); dir != "" {
		add(dir)
	}
	if s.BasePath != "" {
		add(s.BasePath)
	}
	add("/")
	return cands
}

// dirOf 返回 URL 路径的目录部分（不含结尾斜杠），根目录返回空串。
func dirOf(p string) string {
	if p == "" || p == "/" {
		return ""
	}
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return ""
	}
	return p[:i]
}

// Probe 按协议策略探测目标，返回可用站点。
// both 为真时两个协议都返回（各自探活）；否则只返回首个可用协议。
// 返回的 error 仅在所有协议都失败时非空。
func Probe(ctx context.Context, c *httpx.Client, t Target, both bool) ([]*Site, error) {
	var (
		sites   []*Site
		lastErr error
	)
	for _, scheme := range t.PreferredSchemes(both) {
		site, err := probeScheme(ctx, c, t, scheme)
		if err != nil {
			lastErr = err
			continue
		}
		sites = append(sites, site)
		if !both {
			break
		}
	}
	if len(sites) == 0 {
		if lastErr == nil {
			lastErr = errors.New("无可用协议")
		}
		return nil, lastErr
	}
	return sites, nil
}

// probeScheme 用单个协议探测：请求 base-path（或根），必要时补取根路径。
func probeScheme(ctx context.Context, c *httpx.Client, t Target, scheme string) (*Site, error) {
	origin := t.OriginFor(scheme)
	base := t.BasePath
	reqURL := t.URLFor(scheme)
	if base == "" {
		reqURL = origin + "/"
	}

	resp, err := c.Get(ctx, reqURL)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", scheme, err)
	}

	s := &Site{
		Target:       t,
		Scheme:       scheme,
		Origin:       origin,
		BasePath:     base,
		RequestedURL: reqURL,
		Landing:      resp,
		LandingURL:   resp.URL,
		LandingPath:  pathOf(resp.URL),
	}

	// 明文 HTTP 打到 TLS 端口时，服务端会回 400 而不是断连；
	// 这不是“http 可用”，应按该协议失败处理，否则会误报站点。
	if isTLSMismatch(resp) {
		return nil, fmt.Errorf("%s: 明文请求打到 TLS 端口（400）", scheme)
	}

	// base-path 提示失效时补取站点根。
	if base != "" && resp.Status >= 400 {
		if rootResp, rerr := c.Get(ctx, origin+"/"); rerr == nil && !isTLSMismatch(rootResp) {
			s.RootLanding = rootResp
		}
	}
	return s, nil
}

// tlsMismatchMarkers 是各主流服务端在“明文请求打到 TLS 端口”时返回的 400 响应特征。
// 取足够具体的串，避免把正常的 400 业务响应误判为协议不匹配。
var tlsMismatchMarkers = []string{
	"sent an http request to an https server",       // Go net/http
	"the plain http request was sent to https port", // nginx
	"plain http request sent to https port",         // 变体
}

// isTLSMismatch 判断响应是否表示该协议未被服务（明文打到 TLS 端口）。
func isTLSMismatch(resp *httpx.Response) bool {
	if resp == nil || resp.Status != http.StatusBadRequest {
		return false
	}
	body := strings.ToLower(resp.Text())
	for _, m := range tlsMismatchMarkers {
		if strings.Contains(body, m) {
			return true
		}
	}
	return false
}

// pathOf 取 URL 的路径部分；解析失败时返回空串。
func pathOf(rawURL string) string {
	i := strings.Index(rawURL, "://")
	if i < 0 {
		return ""
	}
	rest := rawURL[i+3:]
	j := strings.IndexByte(rest, '/')
	if j < 0 {
		return "/"
	}
	p := rest[j:]
	if k := strings.IndexAny(p, "?#"); k >= 0 {
		p = p[:k]
	}
	return p
}
