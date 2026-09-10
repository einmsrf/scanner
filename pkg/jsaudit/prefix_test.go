package jsaudit

import (
	"reflect"
	"testing"
)

func reportWithPaths(paths ...string) *Report {
	eps := make([]Endpoint, 0, len(paths))
	for _, p := range paths {
		eps = append(eps, Endpoint{Path: p, Count: 1})
	}
	return &Report{Endpoints: eps}
}

func TestBasePrefixCandidatesPicksFrequentAPIPrefix(t *testing.T) {
	// 真实场景：应用挂在 nginx 反代前缀 /api 下。
	// /static 与 /home 出现在前缀停用表里，不应作为候选。
	r := reportWithPaths(
		"/api/v1/users", "/api/v1/orders", "/api/v2/items", "/api/v2/audit", "/api/v3/x",
		"/static/js/a.js", "/static/js/b.js", "/static/css/c.css", "/static/img/d.png", "/static/e.js",
		"/home/index", "/home/list", "/home/detail", "/home/edit",
	)
	got := r.BasePrefixCandidates(3)
	if !reflect.DeepEqual(got, []string{"/api"}) {
		t.Errorf("BasePrefixCandidates = %v, want [/api]（static/home 应被停用表排除）", got)
	}
}

func TestBasePrefixCandidatesRespectsMinCountAndMax(t *testing.T) {
	// 只出现 2 次（< MinPrefixCount=3）不应入选
	below := reportWithPaths("/rare/a", "/rare/b")
	if got := below.BasePrefixCandidates(3); len(got) != 0 {
		t.Errorf("出现次数不足仍入选: %v", got)
	}

	// 多个高频前缀时按次数降序、受 max 限制
	many := reportWithPaths(
		"/alpha/1", "/alpha/2", "/alpha/3", "/alpha/4",
		"/beta/1", "/beta/2", "/beta/3",
		"/gamma/1", "/gamma/2", "/gamma/3",
		"/delta/1", "/delta/2", "/delta/3",
	)
	got := many.BasePrefixCandidates(2)
	if len(got) != 2 {
		t.Fatalf("got = %v, want 2 个", got)
	}
	if got[0] != "/alpha" {
		t.Errorf("首位 = %q, want /alpha（出现次数最多）", got[0])
	}
	// 同频按字典序，beta 在 delta/gamma 之前
	if got[1] != "/beta" {
		t.Errorf("次位 = %q, want /beta（同频按字典序）", got[1])
	}
}

func TestBasePrefixCandidatesSkipsNoise(t *testing.T) {
	r := reportWithPaths(
		"GET", "GET", "GET", // 方法词（且非站内路径）
		"//cdn.example.com/x", "//cdn.example.com/y", "//cdn.example.com/z", // 协议相对
		"/1234/a", "/1234/b", "/1234/c", // 纯数字段
		"/a/x", "/a/y", "/a/z", // 单字符段
		"https://api.x.com/v1/a", "https://api.x.com/v1/b", "https://api.x.com/v1/c", // 绝对 URL
	)
	if got := r.BasePrefixCandidates(5); len(got) != 0 {
		t.Errorf("BasePrefixCandidates = %v, want 空（全是噪声）", got)
	}
}

func TestBasePrefixCandidatesHandlesNilAndZeroMax(t *testing.T) {
	var r *Report
	if got := r.BasePrefixCandidates(3); got != nil {
		t.Errorf("nil report → %v, want nil", got)
	}
	if got := reportWithPaths("/api/a").BasePrefixCandidates(0); got != nil {
		t.Errorf("max=0 → %v, want nil", got)
	}
}
