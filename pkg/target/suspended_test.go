package target

import (
	"strings"
	"testing"

	"github.com/einmsrf/scanner/pkg/httpx"
)

func resp(url, body string) *httpx.Response {
	return &httpx.Response{URL: url, Status: 200, Body: []byte(body)}
}

func TestDetectSuspendedByURL(t *testing.T) {
	cases := []string{
		"http://180.101.238.250:19094/offtime.html",
		"http://x.com/maintenance.html",
		"http://x.com/maintain.html",
		"http://x.com/suspend/index.html",
	}
	for _, u := range cases {
		info := DetectSuspended(resp(u, "<html><body>hello</body></html>"))
		if !info.Suspended {
			t.Errorf("DetectSuspended(%q) = false, want true（URL 含暂停页特征）", u)
		}
		if info.Reason == "" {
			t.Errorf("DetectSuspended(%q) 命中但未给出理由", u)
		}
	}
}

func TestDetectSuspendedByContent(t *testing.T) {
	cases := []string{
		`<html><head><title>系统暂停访问</title></head><body>请稍后再试</body></html>`,
		`<html><body><h1>系统维护中</h1><p>预计 2 小时后恢复</p></body></html>`,
		`<html><body>尊敬的用户，本系统暂停访问，给您带来不便敬请谅解</body></html>`,
		`<html><head><title>网站维护中</title></head><body></body></html>`,
		`<html><body>Sorry, the site is under maintenance. We'll be back soon.</body></html>`,
		`<html><body>Service temporarily unavailable</body></html>`,
	}
	for _, body := range cases {
		info := DetectSuspended(resp("http://x.com/", body))
		if !info.Suspended {
			t.Errorf("DetectSuspended 未识别暂停文案: %s", body)
		}
	}
}

func TestDetectSuspendedNegative(t *testing.T) {
	cases := []string{
		`<html><head><title>Nacos Console</title></head><body>welcome</body></html>`,
		`<html><body><h1>Login</h1><form></form></body></html>`,
		// 普通 404 页不应被当成暂停页
		`<html><head><title>404 Not Found</title></head><body>nginx</body></html>`,
		// "服务" 之类泛词不该误触发
		`<html><body>我们提供优质的云服务与技术支持</body></html>`,
	}
	for _, body := range cases {
		if info := DetectSuspended(resp("http://x.com/", body)); info.Suspended {
			t.Errorf("误判为暂停页: %s（理由 %s）", body, info.Reason)
		}
	}
}

// 只在标题与正文前 8KB 内匹配，避免把正文深处的无关文案当暂停页。
func TestDetectSuspendedOnlyLooksAtHead(t *testing.T) {
	filler := strings.Repeat("a", 9000)
	body := "<html><body>" + filler + "系统暂停访问</body></html>"
	if info := DetectSuspended(resp("http://x.com/", body)); info.Suspended {
		t.Error("正文 8KB 之后的文案不应触发暂停判定")
	}
}

func TestDetectSuspendedNilAndEmpty(t *testing.T) {
	if info := DetectSuspended(nil); info.Suspended {
		t.Error("nil 响应不应判定为暂停")
	}
	if info := DetectSuspended(resp("http://x.com/", "")); info.Suspended {
		t.Error("空响应不应判定为暂停")
	}
}

func TestExtractRawTitle(t *testing.T) {
	cases := map[string]string{
		"<html><title>Hello</title></html>": "Hello",
		"<TITLE>Upper</TITLE>":              "Upper",
		"<title  >  sp  </title>":           "  sp  ",
		"<html>none</html>":                 "",
		"<title>unclosed":                   "",
	}
	for in, want := range cases {
		if got := ExtractRawTitle(in); got != want {
			t.Errorf("ExtractRawTitle(%q) = %q, want %q", in, got, want)
		}
	}
}
