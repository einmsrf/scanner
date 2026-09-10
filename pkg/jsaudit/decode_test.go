package jsaudit

import (
	"strings"
	"testing"
)

// 参考值由 Python 计算（base64 与香农熵）。
func TestEntropyReferenceValues(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"", 0},
		{"admin:abcd@1234", 3.640},
		{"abcd@1234", 3.170},
		{"supersecretvalue", 3.125},
		{"your_password_here", 3.461},
		{"password", 2.750},
		{"123456", 2.585},
		{"P@ssw0rd!2024", 3.239},
		{fakeAWSKey, 3.684},
		{"aaaa", 0},
	}
	for _, c := range cases {
		got := Entropy(c.in)
		if diff := got - c.want; diff > 0.01 || diff < -0.01 {
			t.Errorf("Entropy(%q) = %.3f, want %.3f", c.in, got, c.want)
		}
	}
}

// 设计文档第 7.2 节的典型目标：识别 Basic 头并解码成 user:pass。
func TestDecodeBase64NestedCanonicalExample(t *testing.T) {
	got, depth := DecodeBase64Nested("YWRtaW46YWJjZEAxMjM0", MaxBase64Depth)
	if got != "admin:abcd@1234" {
		t.Errorf("decoded = %q, want admin:abcd@1234", got)
	}
	if depth != 1 {
		t.Errorf("depth = %d, want 1", depth)
	}
	if !CredentialLike(got) {
		t.Error("CredentialLike = false, want true（user:pass 形式）")
	}
}

func TestDecodeBase64NestedTwoLayers(t *testing.T) {
	// base64(base64("supersecretvalue"))
	two := "YzNWd1pYSnpaV055WlhSMllXeDFaUT09"
	got, depth := DecodeBase64Nested(two, MaxBase64Depth)
	if got != "supersecretvalue" {
		t.Errorf("decoded = %q, want supersecretvalue", got)
	}
	if depth != 2 {
		t.Errorf("depth = %d, want 2", depth)
	}
	// 只允许 1 层时不应继续解开
	got1, depth1 := DecodeBase64Nested(two, 1)
	if depth1 != 1 {
		t.Errorf("depth(1) = %d, want 1（受最大层数限制）", depth1)
	}
	if got1 == "supersecretvalue" {
		t.Error("超过最大嵌套层数仍被解开")
	}
}

func TestDecodeBase64NestedLeavesPlainText(t *testing.T) {
	got, depth := DecodeBase64Nested("hello world!", MaxBase64Depth)
	if got != "hello world!" || depth != 0 {
		t.Errorf("got %q depth %d, want 原样返回且 depth 0", got, depth)
	}
}

func TestLooksBase64(t *testing.T) {
	if !LooksBase64("YWRtaW46YWJjZEAxMjM0") {
		t.Error("应识别为标准 base64")
	}
	if !LooksBase64("eyJhbGciOiJIUzI1NiJ9") {
		t.Error("应识别为 base64url")
	}
	if LooksBase64("has space") || LooksBase64("short") {
		t.Error("含空格/过短不应识别为 base64")
	}
}

func TestDecodeJWT(t *testing.T) {
	tok := "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiYWRtaW4iLCAicm9sZSI6ICJyb290In0.c2lnbmF0dXJl"
	h, p, ok := DecodeJWT(tok)
	if !ok {
		t.Fatal("DecodeJWT ok = false")
	}
	if !strings.Contains(h, "HS256") {
		t.Errorf("header = %q, want 含 HS256", h)
	}
	if !strings.Contains(p, "admin") || !strings.Contains(p, "root") {
		t.Errorf("payload = %q, want 含 admin/root", p)
	}
	if _, _, ok := DecodeJWT("not.a.jwt"); ok {
		t.Error("非法 JWT 不应解析成功")
	}
}

func TestIsPlaceholder(t *testing.T) {
	placeholders := []string{
		"your_password_here", "YOUR_API_KEY", "xxxxxxxx", "changeme",
		"placeholder", "password", "123456", "aaaa", "TODO", "null",
		"<your-key>", "${API_KEY}", "example", "sample_value",
	}
	for _, p := range placeholders {
		if !IsPlaceholder(p) {
			t.Errorf("IsPlaceholder(%q) = false, want true", p)
		}
	}
	// 注意：值里含 "example"/"sample" 等词一律判为占位符。真实密钥几乎不会这样，
	// 而 AWS 官方示例密钥（AKIA…EXAMPLE）本就更可能是示例，被过滤是合理的。
	// 形态唯一的规则（AK 前缀/私钥/JWT/Authorization）会绕过这一层，见
	// TestHighConfidenceRulesBypassPlaceholderFilter。
	real := []string{"abcd@1234", "Xk9#mQ2$vL7", "AKIA" + "Z3XQ7YV2N4M5P6R7"}
	for _, r := range real {
		if IsPlaceholder(r) {
			t.Errorf("IsPlaceholder(%q) = true, want false（真实值不应被过滤）", r)
		}
	}
}

func TestCredentialLike(t *testing.T) {
	if !CredentialLike("admin:abcd@1234") {
		t.Error("user:pass 应判定为凭证")
	}
	if CredentialLike("nocolon") || CredentialLike(":pass") || CredentialLike("user:") {
		t.Error("非 user:pass 不应判定为凭证")
	}
	if CredentialLike("has space:pass") {
		t.Error("含空格不应判定为凭证")
	}
}

func TestIsMostlyPrintable(t *testing.T) {
	if !IsMostlyPrintable([]byte("hello world")) {
		t.Error("文本应判定为可打印")
	}
	if IsMostlyPrintable([]byte{0x00, 0x01, 0x02, 0x03}) {
		t.Error("二进制不应判定为可打印")
	}
}

func TestLineOf(t *testing.T) {
	code := "line1\nline2\nline3"
	if got := lineOf(code, 0); got != 1 {
		t.Errorf("offset 0 → line %d, want 1", got)
	}
	if got := lineOf(code, 6); got != 2 {
		t.Errorf("offset 6 → line %d, want 2", got)
	}
	if got := lineOf(code, 12); got != 3 {
		t.Errorf("offset 12 → line %d, want 3", got)
	}
}

func TestAllRulesRegistered(t *testing.T) {
	ids := AllRules()
	// 七类里除“接口路径”外都有正则规则，至少 15 条
	if len(ids) < 15 {
		t.Errorf("规则数 = %d, want >= 15", len(ids))
	}
	want := map[string]bool{
		"auth-basic": false, "auth-bearer": false, "assign-password": false,
		"aws-access-key-id": false, "aliyun-access-key-id": false,
		"tencent-secret-id": false, "jwt": false, "private-key": false,
		"internal-ip": false, "internal-domain": false, "comment-test-account": false,
	}
	for _, id := range ids {
		if _, ok := want[id]; ok {
			want[id] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("缺少规则 %s", id)
		}
	}
}
