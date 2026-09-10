package httpx

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
)

// ErrorClass 是网络失败的大类。
//
// 存在的意义（DESIGN.md 第 9 节实战修订）：实测 113 目标里 77 个失败目标中
// **62 个是超时**、仅 11 个是 connection refused。超时占八成说明主因是
// 出口被丢包/被防护设备限速，而不是目标真死——两者的处置方式完全不同，
// 因此必须分类统计后再决定要不要重试。
type ErrorClass string

// 失败大类。
const (
	ErrClassTimeout  ErrorClass = "timeout"  // 超时（目标慢或出口被丢包/限速）
	ErrClassRefused  ErrorClass = "refused"  // 端口关闭/连接被拒（目标确实没服务）
	ErrClassDNS      ErrorClass = "dns"      // 域名解析失败
	ErrClassTLS      ErrorClass = "tls"      // TLS 握手/证书失败
	ErrClassEOF      ErrorClass = "eof"      // 连接被中途切断（常见于防护设备 RST）
	ErrClassProtocol ErrorClass = "protocol" // 协议层错误（HTTP/2、非法响应等）
	ErrClassOther    ErrorClass = "other"
)

// Display 返回中文说明，便于报告阅读。
func (c ErrorClass) Display() string {
	switch c {
	case ErrClassTimeout:
		return "超时（目标慢或出口被丢包/限速）"
	case ErrClassRefused:
		return "连接被拒（端口未开放）"
	case ErrClassDNS:
		return "域名解析失败"
	case ErrClassTLS:
		return "TLS 握手失败"
	case ErrClassEOF:
		return "连接被切断"
	case ErrClassProtocol:
		return "协议层错误"
	default:
		return "其它错误"
	}
}

// Retryable 判断该错误是否值得重试。
// 只重试瞬时类：超时与被切断。refused / DNS 失败重试没有意义，
// TLS 失败通常也不是瞬时的。
func (c ErrorClass) Retryable() bool {
	return c == ErrClassTimeout || c == ErrClassEOF
}

// ClassifyError 归类网络错误。
func ClassifyError(err error) ErrorClass {
	if err == nil {
		return ErrClassOther
	}
	// 请求预算/主动取消不算网络故障
	if errors.Is(err, ErrBudgetExceeded) {
		return ErrClassOther
	}
	if errors.Is(err, context.Canceled) {
		return ErrClassOther
	}
	// 超时：context deadline 或 net.Error.Timeout()
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrClassTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ErrClassTimeout
	}
	// DNS
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ErrClassDNS
	}
	if errors.Is(err, io.EOF) {
		return ErrClassEOF
	}
	// 字符串兜底：httpx 会把底层错误包在 fmt.Errorf 里，上面两类断言之外
	// 仍需要按文案识别（Windows 与各平台措辞不统一）
	low := strings.ToLower(err.Error())
	switch {
	case strings.Contains(low, "i/o timeout"), strings.Contains(low, "timeout"),
		strings.Contains(low, "deadline exceeded"):
		return ErrClassTimeout
	case strings.Contains(low, "actively refused"), strings.Contains(low, "connection refused"),
		strings.Contains(low, "connectex"):
		return ErrClassRefused
	case strings.Contains(low, "no such host"), strings.Contains(low, "lookup "),
		strings.Contains(low, "dns"):
		return ErrClassDNS
	case strings.Contains(low, "tls"), strings.Contains(low, "x509"),
		strings.Contains(low, "handshake"), strings.Contains(low, "certificate"):
		return ErrClassTLS
	case strings.Contains(low, "eof"), strings.Contains(low, "connection reset"),
		strings.Contains(low, "broken pipe"), strings.Contains(low, "forcibly closed"):
		return ErrClassEOF
	case strings.Contains(low, "http2"), strings.Contains(low, "protocol"),
		strings.Contains(low, "malformed"), strings.Contains(low, "unexpected"):
		return ErrClassProtocol
	}
	return ErrClassOther
}
