package httpx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
)

func TestClassifyErrorRealWorldStrings(t *testing.T) {
	// 全部取自 2026-09-10 晚 113 目标真实扫描报告里的失败信息
	cases := []struct {
		err  string
		want ErrorClass
	}{
		{`http: Get "http://221.226.218.170:18008/": dial tcp 221.226.218.170:18008: connectex: No connection could be made because the target machine actively refused it.`, ErrClassRefused},
		{`https: Get "https://qly.andmu.cn/normal": dial tcp 183.230.102.62:443: i/o timeout`, ErrClassTimeout},
		{`http: Get "http://yp.njyhjs.cn/": dial tcp: lookup yp.njyhjs.cn: no such host`, ErrClassDNS},
		{`http: Get "http://180.101.238.250:19091/": EOF`, ErrClassEOF},
		{`http: Get "http://58.213.138.166:443/": EOF`, ErrClassEOF},
		{`tls: failed to verify certificate: x509: certificate signed by unknown authority`, ErrClassTLS},
		{`http2: unexpected EOF`, ErrClassEOF},
	}
	for _, c := range cases {
		if got := ClassifyError(errors.New(c.err)); got != c.want {
			t.Errorf("ClassifyError(%q) = %q, want %q", c.err, got, c.want)
		}
	}
}

func TestClassifyErrorTypedErrors(t *testing.T) {
	if got := ClassifyError(context.DeadlineExceeded); got != ErrClassTimeout {
		t.Errorf("DeadlineExceeded → %q, want timeout", got)
	}
	if got := ClassifyError(io.EOF); got != ErrClassEOF {
		t.Errorf("io.EOF → %q, want eof", got)
	}
	if got := ClassifyError(&net.DNSError{Err: "no such host", Name: "x"}); got != ErrClassDNS {
		t.Errorf("DNSError → %q, want dns", got)
	}
	// timeout 类型的 net.Error（用 fmt 包装，模拟 httpx 的包装方式）
	wrapped := fmt.Errorf("httpx: %w", timeoutErr{})
	if got := ClassifyError(wrapped); got != ErrClassTimeout {
		t.Errorf("包装后的 net.Error(timeout) → %q, want timeout", got)
	}
	// 预算耗尽不算网络故障
	if got := ClassifyError(fmt.Errorf("x: %w", ErrBudgetExceeded)); got != ErrClassOther {
		t.Errorf("预算耗尽 → %q, want other", got)
	}
	if got := ClassifyError(nil); got != ErrClassOther {
		t.Errorf("nil → %q, want other", got)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestErrorClassRetryable(t *testing.T) {
	retryable := map[ErrorClass]bool{
		ErrClassTimeout: true,
		ErrClassEOF:     true,
		ErrClassRefused: false, // 重试无意义
		ErrClassDNS:     false,
		ErrClassTLS:     false,
		ErrClassOther:   false,
	}
	for c, want := range retryable {
		if got := c.Retryable(); got != want {
			t.Errorf("%s.Retryable() = %v, want %v", c, got, want)
		}
	}
}

func TestErrorClassDisplay(t *testing.T) {
	for _, c := range []ErrorClass{ErrClassTimeout, ErrClassRefused, ErrClassDNS, ErrClassTLS, ErrClassEOF, ErrClassProtocol, ErrClassOther} {
		if c.Display() == "" || c.Display() == string(c) {
			t.Errorf("%s.Display() = %q, 期望中文说明", c, c.Display())
		}
	}
}
