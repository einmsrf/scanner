package fingerprint

import (
	"strconv"
	"testing"
)

// 参考值由 Python mmh3 库（mmh3.hash）生成，确保实现与上游一致。
func TestMMH3ReferenceVectors(t *testing.T) {
	cases := []struct {
		in   string
		want int32
	}{
		{"", 0},
		{"hello", 613153351},
		{"foo", -156908512},
		{"test", -1167338989},
		{"The quick brown fox", 1621279277},
		{"\x00\x01\x02\x03", -188683207},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", -1896897432},
	}
	for _, c := range cases {
		if got := MMH3([]byte(c.in)); got != c.want {
			t.Errorf("MMH3(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestMD5HexReference(t *testing.T) {
	// 参考值由 Python hashlib.md5 生成。
	got := MD5Hex([]byte("<html>fav</html>"))
	want := "6a8f8d3d64508826ee23295ae12139dc"
	if got != want {
		t.Errorf("MD5Hex = %q, want %q", got, want)
	}
}

func TestFaviconMatchesMD5(t *testing.T) {
	icon := []byte("<html>fav</html>")
	hashes := []string{"6a8f8d3d64508826ee23295ae12139dc"}
	if !FaviconMatches(hashes, icon) {
		t.Error("FaviconMatches = false, want true（md5 命中）")
	}
	// 大小写不敏感
	if !FaviconMatches([]string{"6A8F8D3D64508826EE23295AE12139DC"}, icon) {
		t.Error("md5 应大小写不敏感")
	}
	if FaviconMatches([]string{"00000000000000000000000000000000"}, icon) {
		t.Error("FaviconMatches = true, want false（不同哈希不应命中）")
	}
}

func TestFaviconMatchesMMH3(t *testing.T) {
	icon := []byte("hello")
	want := strconv.FormatInt(int64(613153351), 10)
	if !FaviconMatches([]string{want}, icon) {
		t.Errorf("FaviconMatches 未命中 mmh3 十进制写法 %s", want)
	}
	// "foo" → mmh3 = -156908512，有符号十六进制 -95a3be0 / 无符号 f6a5c420。
	if !FaviconMatches([]string{"-95a3be0"}, []byte("foo")) {
		t.Error("FaviconMatches 未命中 mmh3 有符号十六进制写法")
	}
	if !FaviconMatches([]string{"f6a5c420"}, []byte("foo")) {
		t.Error("FaviconMatches 未命中 mmh3 无符号十六进制写法")
	}
	if !FaviconMatches([]string{"0xf6a5c420"}, []byte("foo")) {
		t.Error("FaviconMatches 未处理 0x 前缀")
	}
	if !FaviconMatches([]string{"-156908512"}, []byte("foo")) {
		t.Error("FaviconMatches 未命中 mmh3 负数写法")
	}
}

func TestMMH3HexForms(t *testing.T) {
	// 参考值由 Python mmh3 + format() 生成。
	if got := MMH3Hex([]byte("foo")); got != "-95a3be0" {
		t.Errorf("MMH3Hex(foo) = %q, want -95a3be0", got)
	}
	if got := MMH3HexUnsigned([]byte("foo")); got != "f6a5c420" {
		t.Errorf("MMH3HexUnsigned(foo) = %q, want f6a5c420", got)
	}
}

func TestFaviconMatchesDoesNotConfuseMD5AndMMH3(t *testing.T) {
	// 32 位十六进制且恰好是 md5 → 命中 md5；不应被 mmh3 比较污染。
	icon := []byte("<html>fav</html>")
	if !FaviconMatches([]string{"6a8f8d3d64508826ee23295ae12139dc"}, icon) {
		t.Error("md5 应命中")
	}
	if FaviconMatches([]string{"deadbeef"}, icon) {
		t.Error("无关短十六进制不应命中")
	}
}

func TestFaviconMatchesEmptyInputs(t *testing.T) {
	if FaviconMatches(nil, []byte("x")) {
		t.Error("空哈希列表不应命中")
	}
	if FaviconMatches([]string{"abc"}, nil) {
		t.Error("空 favicon 不应命中")
	}
}
