// Package jsaudit 实现 JS 审计：收集 JS（含 sourcemap）、按七类规则提取敏感信息。
//
// 铁律（DESIGN.md 第 1 节）：只分析，绝不主动请求 JS 里发现的接口。
package jsaudit

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
)

// EntropyThreshold 是“疑似密钥”的熵值门槛（DESIGN.md 第 7.2 节：>4.0）。
// 只用于“靠形态猜测”的场景；带明确前缀/关键字的高置信规则不受此限制。
const EntropyThreshold = 4.0

// MaxBase64Depth 是 base64 最多嵌套解码层数（DESIGN.md 第 7.2 节）。
const MaxBase64Depth = 2

// Entropy 计算字符串的香农熵（bits/char）。空串返回 0。
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// LooksBase64 粗略判断是否是 base64/base64url 串（长度、字符集、含填充）。
func LooksBase64(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 8 {
		return false
	}
	pad := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+' || c == '/' || c == '-' || c == '_':
		case c == '=':
			pad++
		default:
			return false
		}
	}
	return pad <= 2
}

// IsMostlyPrintable 判断解码结果是否像文本（可打印字符占比 >= 90%）。
func IsMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	ok := 0
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c < 0x7f) || c >= 0x80 {
			ok++
		}
	}
	return float64(ok)/float64(len(b)) >= 0.9
}

// DecodeBase64Nested 最多解码 maxDepth 层 base64，返回最终结果与实际层数。
// 非 base64 或解码结果不像文本时原样返回、层数为 0。
func DecodeBase64Nested(s string, maxDepth int) (string, int) {
	if maxDepth <= 0 {
		maxDepth = MaxBase64Depth
	}
	cur := strings.TrimSpace(s)
	depth := 0
	for depth < maxDepth {
		if !LooksBase64(cur) {
			break
		}
		raw, err := decodeB64(cur)
		if err != nil || !IsMostlyPrintable(raw) {
			break
		}
		next := string(raw)
		// 解出的内容必须真的“更可读”才认为解码有意义，避免把普通 token 解成乱码。
		if strings.TrimSpace(next) == "" || next == cur {
			break
		}
		cur = next
		depth++
	}
	if depth == 0 {
		return s, 0
	}
	return cur, depth
}

// decodeB64 兼容标准与 URL-safe、带/不带填充的 base64。
func decodeB64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if raw, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	if raw, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	b := []byte(s)
	n := len(b) % 4
	if n != 0 {
		b = append(b, strings.Repeat("=", 4-n)...)
	}
	if raw, err := base64.StdEncoding.DecodeString(string(b)); err == nil {
		return raw, nil
	}
	return base64.URLEncoding.DecodeString(string(b))
}

// DecodeJWT 解析 JWT 的 header 与 payload（不解码签名，也不做任何校验）。
// 返回可读的 JSON 字符串，解析失败时 ok 为 false。
func DecodeJWT(tok string) (header, payload string, ok bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", "", false
	}
	hb, err := decodeB64(parts[0])
	if err != nil {
		return "", "", false
	}
	pb, err := decodeB64(parts[1])
	if err != nil {
		return "", "", false
	}
	return compactJSON(hb), compactJSON(pb), true
}

// compactJSON 把 JSON 压成单行，便于报告展示；非法 JSON 原样返回。
func compactJSON(b []byte) string {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return string(b)
	}
	return string(out)
}

// placeholderTokens 是明显的占位符/示例值，命中即不当作真实密钥。
var placeholderTokens = []string{
	"your_", "your-", "yourkey", "xxxx", "changeme", "change_me", "placeholder",
	"replace_me", "replaceme", "todo", "fixme", "dummy", "example", "sample",
	"abcdefg", "<", ">", "{{", "}}", "${", "null", "undefined", "none",
	"****", "......", "aaaaaa", "000000",
}

// IsPlaceholder 判断捕获到的值是否是占位符/示例值。
func IsPlaceholder(v string) bool {
	t := strings.ToLower(strings.TrimSpace(v))
	if t == "" {
		return true
	}
	// 纯重复字符（如 aaaa、1111）几乎不可能是密钥
	if isRepeatedRune(t) {
		return true
	}
	// 常见弱口令/占位词整体相等
	switch t {
	case "password", "passwd", "pwd", "secret", "token", "test", "admin",
		"123456", "12345678", "123456789", "1234567890", "qwerty", "root":
		return true
	}
	for _, p := range placeholderTokens {
		if strings.Contains(t, p) {
			return true
		}
	}
	return false
}

func isRepeatedRune(s string) bool {
	if len(s) < 3 {
		return false
	}
	first := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			return false
		}
	}
	return true
}

// CredentialLike 判断解出的 base64 是否像 `user:pass` 形式。
func CredentialLike(s string) bool {
	i := strings.IndexByte(s, ':')
	if i <= 0 || i >= len(s)-1 {
		return false
	}
	user, pass := s[:i], s[i+1:]
	return len(user) >= 2 && len(pass) >= 2 && !strings.ContainsAny(user, " \n\r\t") && !strings.ContainsAny(pass, " \n\r\t")
}

// SplitLines 返回 1-based 行号，便于报告定位。
func lineOf(code string, offset int) int {
	if offset <= 0 {
		return 1
	}
	if offset > len(code) {
		offset = len(code)
	}
	return 1 + strings.Count(code[:offset], "\n")
}
