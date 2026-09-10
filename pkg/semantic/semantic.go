// Package semantic 实现可降级的 LLM 语义层：把正则初筛后的可疑片段批量送给
// OpenAI 兼容接口打分，降低误报。
//
// 降级原则（DESIGN.md 第 8 节）：未配置 api_key 或接口不可用时静默关闭，
// 不影响其余扫描功能；调用方用 Enabled() 判断，Score 返回的可读错误只用于提示。
//
// 数据外发提示：本模块会把目标站点的 JS 片段与接口路径发送给第三方 API，
// README 中已明示该风险。
package semantic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/einmsrf/scanner/pkg/httpx"
)

// 默认值。
const (
	DefaultTimeout  = 60 * time.Second // 批量打分整体超时
	DefaultMaxItems = 120              // 单次扫描最多外发的条目数（控制成本）
	DefaultMaxBatch = 40               // 单次请求包含的条目数
	maxReasonLen    = 200
	maxTextLen      = 1200 // 单条片段送入模型前的截断长度
)

// ErrDisabled 表示语义层未启用（缺少 api_key）。
var ErrDisabled = errors.New("semantic: 未配置 api_key，语义层已关闭")

// ErrTooManyItems 表示条目数超过上限。
var ErrTooManyItems = errors.New("semantic: 外发条目数超过上限")

// Options 是语义层配置。
type Options struct {
	BaseURL string // 如 https://api.deepseek.com/v1
	APIKey  string
	Model   string
	Timeout time.Duration
	Proxy   string // 为空时回退 HTTPS_PROXY/HTTP_PROXY 环境变量
	// MaxItems 为单次扫描最多外发的条目数；<=0 取默认。
	MaxItems int
	// MaxBatch 为单个请求包含的条目数；<=0 取默认。
	MaxBatch int
}

// Kind 标注条目类型，供模型区分判断标准。
type Kind string

// 条目类型。
const (
	KindSnippet  Kind = "snippet"  // 疑似敏感字符串片段
	KindEndpoint Kind = "endpoint" // 提取到的接口路径
)

// Item 是一条待判定条目。
type Item struct {
	ID   string // 稳定标识，用于把判定结果对应回原条目
	Text string // 待判定文本（带上下文）
	Kind Kind
}

// Verdict 是模型对一条条目的判定。
type Verdict struct {
	ID          string
	IsSensitive bool
	Reason      string
	Confidence  float64
	// Judged 为 false 表示模型没有返回该条目的判定（此时报告按纯正则结果展示）。
	Judged bool
}

// Client 是语义层客户端，可安全并发复用。
type Client struct {
	opts Options
	hc   *httpx.Client
}

// New 创建语义层客户端。api_key 为空时返回 ErrDisabled。
func New(opts Options) (*Client, error) {
	if strings.TrimSpace(opts.APIKey) == "" {
		return nil, ErrDisabled
	}
	if strings.TrimSpace(opts.BaseURL) == "" {
		return nil, errors.New("semantic: base_url 不能为空")
	}
	if strings.TrimSpace(opts.Model) == "" {
		return nil, errors.New("semantic: model 不能为空")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxItems <= 0 {
		opts.MaxItems = DefaultMaxItems
	}
	if opts.MaxBatch <= 0 {
		opts.MaxBatch = DefaultMaxBatch
	}

	hc, err := httpx.New(httpx.Options{
		Timeout:     opts.Timeout,
		QPS:         -1, // 不做请求间隔限制
		Proxy:       opts.Proxy,
		MaxRequests: 10000,
		MaxBody:     4 << 20,
	})
	if err != nil {
		return nil, fmt.Errorf("semantic: 创建 HTTP 客户端失败: %w", err)
	}
	return &Client{opts: opts, hc: hc}, nil
}

// Enabled 恒为 true（创建失败时调用方拿不到 Client）；保留以便调用点可读。
func (c *Client) Enabled() bool { return c != nil }

// Model 返回使用的模型名。
func (c *Client) Model() string {
	if c == nil {
		return ""
	}
	return c.opts.Model
}

// Close 释放连接。
func (c *Client) Close() {
	if c != nil && c.hc != nil {
		c.hc.Close()
	}
}

// chatRequest 是 OpenAI 兼容的对话请求体。
type chatRequest struct {
	Model       string    `json:"model"`
	Messages    []message `json:"messages"`
	Temperature float64   `json:"temperature"`
	Stream      bool      `json:"stream"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatResponse 只取我们关心的字段。
type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// rawVerdict 对应设计文档要求的返回结构 [{item, is_sensitive, reason, confidence}]。
type rawVerdict struct {
	Item        string  `json:"item"`
	IsSensitive bool    `json:"is_sensitive"`
	Reason      string  `json:"reason"`
	Confidence  float64 `json:"confidence"`
}

// Score 批量判定条目，返回按输入顺序排列的结果（含未判定的占位项）。
// 条目为空时直接返回 nil，不发起任何请求。
func (c *Client) Score(ctx context.Context, items []Item) ([]Verdict, error) {
	if c == nil {
		return nil, ErrDisabled
	}
	if len(items) == 0 {
		return nil, nil
	}
	if len(items) > c.opts.MaxItems {
		items = items[:c.opts.MaxItems]
	}

	byID := map[string]int{}
	for i, it := range items {
		byID[it.ID] = i
	}
	out := make([]Verdict, len(items))
	for i, it := range items {
		out[i] = Verdict{ID: it.ID, Judged: false, Reason: ""}
	}

	var firstErr error
	for start := 0; start < len(items); start += c.opts.MaxBatch {
		end := start + c.opts.MaxBatch
		if end > len(items) {
			end = len(items)
		}
		verdicts, err := c.scoreBatch(ctx, items[start:end])
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue // 单批失败不影响其它批次，最终按未判定处理
		}
		for _, v := range verdicts {
			idx, ok := byID[v.ID]
			if !ok {
				continue // 模型返回了不认识的 item，忽略
			}
			v.Judged = true
			out[idx] = v
		}
	}
	return out, firstErr
}

// scoreBatch 发送单批请求。
func (c *Client) scoreBatch(ctx context.Context, batch []Item) ([]Verdict, error) {
	body, err := json.Marshal(chatRequest{
		Model:       c.opts.Model,
		Temperature: 0,
		Stream:      false,
		Messages: []message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: buildUserPrompt(batch)},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("semantic: 构造请求失败: %w", err)
	}

	url := strings.TrimSuffix(c.opts.BaseURL, "/") + "/chat/completions"
	resp, err := c.hc.Do(ctx, &httpx.Request{
		Method: "POST",
		URL:    url,
		Headers: map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + c.opts.APIKey,
		},
		Body: body,
	})
	if err != nil {
		return nil, fmt.Errorf("semantic: 请求失败: %w", err)
	}
	if resp.Status >= 400 {
		return nil, fmt.Errorf("semantic: 接口返回 HTTP %d: %s", resp.Status, clipText(resp.Text(), 200))
	}

	var cr chatResponse
	if err := json.Unmarshal(resp.Body, &cr); err != nil {
		return nil, fmt.Errorf("semantic: 响应不是合法 JSON: %w", err)
	}
	if cr.Error != nil {
		return nil, fmt.Errorf("semantic: 接口报错: %s", cr.Error.Message)
	}
	if len(cr.Choices) == 0 {
		return nil, errors.New("semantic: 响应中没有 choices")
	}
	return parseVerdicts(cr.Choices[0].Message.Content)
}

// parseVerdicts 宽容解析模型输出：兼容裸数组、Markdown 代码块包裹、
// 以及被包在 {"results":[...]} 里的形式（部分接口开 json_object 模式时会这样）。
func parseVerdicts(content string) ([]Verdict, error) {
	s := stripFences(strings.TrimSpace(content))

	if arr, ok := extractJSONArray(s); ok {
		var raws []rawVerdict
		if err := json.Unmarshal(arr, &raws); err == nil {
			return toVerdicts(raws), nil
		}
	}
	if obj, ok := extractJSONObject(s); ok {
		var wrapper struct {
			Results []rawVerdict `json:"results"`
			Items   []rawVerdict `json:"items"`
			Data    []rawVerdict `json:"data"`
		}
		if err := json.Unmarshal(obj, &wrapper); err == nil {
			for _, list := range [][]rawVerdict{wrapper.Results, wrapper.Items, wrapper.Data} {
				if len(list) > 0 {
					return toVerdicts(list), nil
				}
			}
		}
	}
	return nil, fmt.Errorf("semantic: 无法从模型输出解析出 JSON 结果: %s", clipText(s, 200))
}

// stripFences 去掉 Markdown 代码块围栏。
func stripFences(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, "```"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// extractJSONArray 取第一个 '[' 到最后一个 ']' 之间的子串。
func extractJSONArray(s string) ([]byte, bool) {
	lo := strings.IndexByte(s, '[')
	hi := strings.LastIndexByte(s, ']')
	if lo < 0 || hi <= lo {
		return nil, false
	}
	return []byte(s[lo : hi+1]), true
}

// extractJSONObject 取第一个 '{' 到最后一个 '}' 之间的子串。
func extractJSONObject(s string) ([]byte, bool) {
	lo := strings.IndexByte(s, '{')
	hi := strings.LastIndexByte(s, '}')
	if lo < 0 || hi <= lo {
		return nil, false
	}
	return []byte(s[lo : hi+1]), true
}

// toVerdicts 归一化模型返回的结果（截断理由、钳制置信度）。
func toVerdicts(raws []rawVerdict) []Verdict {
	out := make([]Verdict, 0, len(raws))
	for _, r := range raws {
		id := strings.TrimSpace(r.Item)
		if id == "" {
			continue
		}
		conf := r.Confidence
		if conf < 0 {
			conf = 0
		}
		if conf > 1 {
			conf = 1
		}
		out = append(out, Verdict{
			ID:          id,
			IsSensitive: r.IsSensitive,
			Reason:      clipText(strings.TrimSpace(r.Reason), maxReasonLen),
			Confidence:  conf,
			Judged:      true,
		})
	}
	return out
}

const systemPrompt = `你是 Web 安全审计助手。用户会给你若干条从目标站点前端 JS 中提取的文本片段，` +
	`请逐条判断它是否是真实的敏感信息（真实密钥/口令/令牌/内网地址/危险接口），` +
	`还是误报（占位符、示例值、公开常量、框架内置字符串、无意义的短字符串）。` +
	`对接口路径：判断它是否像高权限或高危接口（管理后台、内部接口、删除/重置/导出等），` +
	`普通业务查询接口不算敏感。` +
	`只输出 JSON 数组，不要输出任何解释或 Markdown 代码块。`

func buildUserPrompt(batch []Item) string {
	var b strings.Builder
	b.WriteString("待判定条目如下（item 为条目标识）：\n\n")
	for _, it := range batch {
		b.WriteString("item: ")
		b.WriteString(it.ID)
		b.WriteString("\ntype: ")
		b.WriteString(string(it.Kind))
		b.WriteString("\ntext: ")
		b.WriteString(clipText(it.Text, maxTextLen))
		b.WriteString("\n---\n")
	}
	b.WriteString("\n请严格按以下 JSON 数组格式返回，每个条目一项：\n")
	b.WriteString(`[{"item":"条目标识","is_sensitive":true或false,"reason":"简短中文理由","confidence":0到1的小数}]`)
	b.WriteString("\n不要遗漏任何 item，不要新增 item。")
	return b.String()
}

// clipText 压成单行并截断，避免超长片段浪费 token。
func clipText(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) > max {
		return string(r[:max]) + "…"
	}
	return s
}
