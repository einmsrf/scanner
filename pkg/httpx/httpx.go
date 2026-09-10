// Package httpx 提供目标级 HTTP 客户端：跟随重定向、跳过证书验证、限速、
// 请求预算与 404 基线。所有网络访问都经过这里，便于统一限速与统计。
package httpx

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 默认值。调用方可经 Options 覆盖。
const (
	DefaultTimeout      = 10 * time.Second
	DefaultQPS          = 5.0
	DefaultMaxBody      = 4 << 20 // 4MB，单页面上限
	DefaultMaxRedirects = 10
	DefaultMaxRequests  = 100 // 单目标请求预算硬上限，见 DESIGN.md 第 5.2 节
	DefaultUserAgent    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
	DefaultDialTimeout  = 8 * time.Second
	DefaultTLSHandshake = 8 * time.Second
)

// ErrBudgetExceeded 表示该目标的请求数已用尽。
var ErrBudgetExceeded = errors.New("httpx: 单目标请求预算已用尽")

// Options 是客户端配置。零值字段取默认值。
type Options struct {
	Timeout       time.Duration // 单请求超时
	QPS           float64       // 单目标每秒请求数上限，<=0 表示不限速
	Proxy         string        // 如 http://127.0.0.1:7890；为空时回退 HTTPS_PROXY 环境变量
	MaxBody       int64         // 单响应体读取上限（字节）
	MaxRedirects  int           // 最大重定向次数
	MaxRequests   int           // 单目标请求预算；<=0 表示默认上限
	UserAgent     string
	InsecureTLS   bool     // 跳过证书校验；默认 true（大量目标为自签证书或 IP 直连）
	VerifyTLSFlag bool     // 显式要求校验证书时置位（供 CLI --verify-tls 使用）
	ExtraRootCAs  []string // 保留字段，暂未使用
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.QPS == 0 {
		o.QPS = DefaultQPS
	}
	if o.MaxBody <= 0 {
		o.MaxBody = DefaultMaxBody
	}
	if o.MaxRedirects <= 0 {
		o.MaxRedirects = DefaultMaxRedirects
	}
	if o.MaxRequests <= 0 {
		o.MaxRequests = DefaultMaxRequests
	}
	if o.UserAgent == "" {
		o.UserAgent = DefaultUserAgent
	}
	// 默认跳过证书校验：除非调用方显式要求校验。
	if !o.VerifyTLSFlag {
		o.InsecureTLS = true
	}
	return o
}

// Request 是一次请求的描述。MaxBody 为 0 时用客户端默认值。
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte // 非空时作为请求体发送（用于 POST，如语义层调用）
	MaxBody int64
}

// Response 是读取完毕的响应。Body 为原始字节（可能是截断后的），
// 既供文本匹配也供 favicon 哈希计算。
type Response struct {
	URL       string // 重定向后的最终 URL
	Status    int
	Header    http.Header
	Body      []byte
	Truncated bool // 响应体超过上限被截断
	Duration  time.Duration
	Redirects []string // 中间跳转的 URL 链
}

// Text 返回响应体字符串。
func (r *Response) Text() string { return string(r.Body) }

// HeaderGet 便捷读取响应头（大小写不敏感，取第一个值）。
func (r *Response) HeaderGet(key string) string { return r.Header.Get(key) }

// ContentType 返回去掉参数部分的 Content-Type。
func (r *Response) ContentType() string {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// IsHTML 判断响应是否为 HTML 文档。
func (r *Response) IsHTML() bool {
	ct := r.ContentType()
	return strings.Contains(ct, "html") || strings.Contains(ct, "xhtml")
}

// Client 是绑定了单个目标限速与预算的 HTTP 客户端。
// 并发调用 Do 是安全的。
type Client struct {
	opts Options
	hc   *http.Client
	lim  *limiter

	budget    int64 // 剩余可用请求数
	budgetMax int64
	used      int64
}

// New 创建一个客户端。opts.Proxy 为空时回退到 HTTPS_PROXY / HTTP_PROXY 环境变量。
func New(opts Options) (*Client, error) {
	opts = opts.withDefaults()

	proxyFn := http.ProxyFromEnvironment
	if opts.Proxy != "" {
		pu, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("httpx: 代理地址无效 %q: %w", opts.Proxy, err)
		}
		proxyFn = http.ProxyURL(pu)
	}

	tr := &http.Transport{
		Proxy: proxyFn,
		DialContext: (&net.Dialer{
			Timeout:   DefaultDialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   DefaultTLSHandshake,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.InsecureTLS, // #nosec G402 -- 设计上跳过，目标多为自签证书
		},
	}

	c := &Client{
		opts:      opts,
		lim:       newLimiter(opts.QPS),
		budgetMax: int64(opts.MaxRequests),
	}
	c.budget = c.budgetMax

	c.hc = &http.Client{
		Transport: tr,
		Timeout:   opts.Timeout,
	}
	return c, nil
}

// Get 发起 GET 请求。
func (c *Client) Get(ctx context.Context, rawURL string) (*Response, error) {
	return c.Do(ctx, &Request{Method: http.MethodGet, URL: rawURL})
}

// Do 发起请求，自动限速并扣减预算。返回的 *Response 在状态码非 2xx 时也不为 error，
// 只有网络层失败才算 error。
func (c *Client) Do(ctx context.Context, req *Request) (*Response, error) {
	if req == nil || req.URL == "" {
		return nil, errors.New("httpx: 请求 URL 为空")
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	// 畸形 URL（如 //static/... 双斜杠）在调用侧归一化，这里兜底补 scheme。
	target := req.URL
	if strings.HasPrefix(target, "//") {
		target = "https:" + target
	}

	if err := c.spend(); err != nil {
		return nil, err
	}
	if err := c.lim.wait(ctx); err != nil {
		return nil, err
	}

	maxBody := req.MaxBody
	if maxBody <= 0 {
		maxBody = c.opts.MaxBody
	}

	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}
	hreq, err := http.NewRequestWithContext(ctx, method, target, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("httpx: 构造请求失败: %w", err)
	}
	hreq.Header.Set("User-Agent", c.opts.UserAgent)
	hreq.Header.Set("Accept", "*/*")
	hreq.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	for k, v := range req.Headers {
		hreq.Header.Set(k, v)
	}

	var (
		mu        sync.Mutex
		redirects []string
	)
	hc := *c.hc // 浅拷贝，仅为本请求挂 CheckRedirect
	hc.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) >= c.opts.MaxRedirects {
			return fmt.Errorf("httpx: 重定向超过 %d 次", c.opts.MaxRedirects)
		}
		mu.Lock()
		redirects = append(redirects, r.URL.String())
		mu.Unlock()
		return nil
	}

	start := time.Now()
	resp, err := hc.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, truncated, err := readCapped(resp.Body, maxBody)
	if err != nil {
		return nil, fmt.Errorf("httpx: 读取响应体失败: %w", err)
	}

	mu.Lock()
	chain := redirects
	mu.Unlock()

	return &Response{
		URL:       resp.Request.URL.String(),
		Status:    resp.StatusCode,
		Header:    resp.Header,
		Body:      body,
		Truncated: truncated,
		Duration:  time.Since(start),
		Redirects: chain,
	}, nil
}

// readCapped 读取至多 max 字节，返回是否被截断。
func readCapped(r io.Reader, max int64) ([]byte, bool, error) {
	buf, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(buf)) > max {
		return buf[:max], true, nil
	}
	return buf, false, nil
}

// spend 扣减一次请求预算。
func (c *Client) spend() error {
	for {
		cur := atomic.LoadInt64(&c.budget)
		if cur <= 0 {
			return fmt.Errorf("%w（上限 %d）", ErrBudgetExceeded, c.budgetMax)
		}
		if atomic.CompareAndSwapInt64(&c.budget, cur, cur-1) {
			atomic.AddInt64(&c.used, 1)
			return nil
		}
	}
}

// Used 返回已发出的请求数。
func (c *Client) Used() int { return int(atomic.LoadInt64(&c.used)) }

// Remaining 返回剩余请求预算。
func (c *Client) Remaining() int { return int(atomic.LoadInt64(&c.budget)) }

// BudgetMax 返回请求预算上限。
func (c *Client) BudgetMax() int { return int(c.budgetMax) }

// Options 返回生效后的配置副本。
func (c *Client) Options() Options { return c.opts }

// Close 释放空闲连接。
func (c *Client) Close() {
	if tr, ok := c.hc.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

// limiter 是均匀间隔的令牌限速器：每次 wait 预留一个时间片，
// 从而使每秒放行次数不超过 QPS，且对并发调用有序。
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newLimiter(qps float64) *limiter {
	l := &limiter{}
	if qps > 0 {
		l.interval = time.Duration(float64(time.Second) / qps)
	}
	return l
}

func (l *limiter) wait(ctx context.Context) error {
	if l.interval <= 0 {
		return nil
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
