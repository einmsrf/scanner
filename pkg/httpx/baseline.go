package httpx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
)

// BaselinePrefix 是 404 基线探测路径的前缀。
// 用不会与真实资源重名的随机串，避免误命中。
const BaselinePrefix = ".scanner-nonexistent-"

// Baseline 记录目标对“不存在的路径”的响应特征，用于区分真实命中与通配/软 404。
type Baseline struct {
	Path        string // 实际请求的随机路径
	Status      int
	ContentType string
	BodyLen     int
	BodySHA256  string
	// Wildcard 为 true 表示该站点对不存在的路径也返回 2xx/3xx
	// （SPA 或软 404），此时必须比对响应体才能判定命中。
	Wildcard bool
}

// FetchBaselineAt 针对指定 origin（如 https://example.com 或 http://1.2.3.4:8080）
// 请求一个随机不存在路径并记录返回特征，遵循 DESIGN.md 第 6 节。
func (c *Client) FetchBaselineAt(ctx context.Context, origin string) (*Baseline, error) {
	if origin == "" {
		return nil, fmt.Errorf("httpx: 基线探测需要 origin")
	}
	p := BaselinePrefix + randToken(10)
	resp, err := c.Get(ctx, strings.TrimSuffix(origin, "/")+"/"+p)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(normalizeBody(resp.Body))
	return &Baseline{
		Path:        p,
		Status:      resp.Status,
		ContentType: resp.ContentType(),
		BodyLen:     len(resp.Body),
		BodySHA256:  hex.EncodeToString(sum[:]),
		Wildcard:    resp.Status < 400,
	}, nil
}

// SameAs 判断 resp 是否与基线无法区分（即“实际不存在”）。
// 供 probe 过滤通配响应导致的误报。
func (b *Baseline) SameAs(resp *Response) bool {
	if b == nil || resp == nil {
		return false
	}
	if resp.Status != b.Status {
		return false
	}
	sum := sha256.Sum256(normalizeBody(resp.Body))
	if hex.EncodeToString(sum[:]) == b.BodySHA256 {
		return true
	}
	// 动态页面（含随机 token、时间戳）哈希会不同：通配站点再按
	// 长度接近 + 同 Content-Type 容差判定。
	if b.Wildcard && resp.ContentType() == b.ContentType {
		return lengthClose(len(resp.Body), b.BodyLen, 0.03)
	}
	return false
}

// String 便于日志输出。
func (b *Baseline) String() string {
	return fmt.Sprintf("status=%d len=%d ct=%s wildcard=%v", b.Status, b.BodyLen, b.ContentType, b.Wildcard)
}

// lengthClose 判断 a、b 相对差是否在 tol 以内。两者都为 0 视为接近。
func lengthClose(a, b int, tol float64) bool {
	if a == b {
		return true
	}
	max := a
	if b > max {
		max = b
	}
	if max == 0 {
		return true
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return float64(diff)/float64(max) <= tol
}

// normalizeBody 折叠空白，降低仅格式差异（缩进、换行）带来的干扰。
func normalizeBody(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	out := make([]byte, 0, len(b))
	space := false
	for _, ch := range b {
		switch ch {
		case ' ', '\t', '\r', '\n':
			space = true
		default:
			if space && len(out) > 0 {
				out = append(out, ' ')
			}
			space = false
			out = append(out, ch)
		}
	}
	return out
}

const tokenAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

func randToken(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = tokenAlphabet[rand.Intn(len(tokenAlphabet))]
	}
	return string(b)
}
