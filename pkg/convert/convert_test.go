package convert

import (
	"encoding/json"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/einmsrf/scanner/pkg/fingerprint"
)

func TestParseTemplateWordMatcher(t *testing.T) {
	tpl, err := ParseTemplate([]byte(`
id: alibaba-nacos
info:
  name: alibaba-nacos
  tags: detect,tech,alibaba-nacos
  metadata:
    product: nacos
    vendor: alibaba
http:
- method: GET
  path:
  - '{{BaseURL}}/'
  - '{{BaseURL}}/nacos/'
  matchers:
  - type: word
    words:
    - <title>nacos</title>
    case-insensitive: true
`))
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	rules, dm, dr := tpl.Rules()
	if dm != 0 || dr != 0 {
		t.Errorf("dropped = %d/%d, want 0/0", dm, dr)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	r := rules[0]
	if r.ID != "alibaba-nacos" || r.Product != "nacos" || r.Vendor != "alibaba" {
		t.Errorf("rule = %+v", r)
	}
	if len(r.Paths) != 2 || r.Paths[0] != "/" || r.Paths[1] != "/nacos/" {
		t.Errorf("Paths = %v, want [/ /nacos/]", r.Paths)
	}
	if len(r.Tags) != 1 || r.Tags[0] != "alibaba-nacos" {
		t.Errorf("Tags = %v, want 去掉 detect/tech 后仅 [alibaba-nacos]", r.Tags)
	}
	m := r.Matchers[0]
	if m.Type != fingerprint.MatcherWord || !m.CI || len(m.Value) != 1 {
		t.Errorf("matcher = %+v", m)
	}
	if m.Condition() != fingerprint.CondOr {
		t.Errorf("缺省 condition = %q, want or", m.Condition())
	}
}

func TestParseTemplateFaviconAndRegex(t *testing.T) {
	tpl, err := ParseTemplate([]byte(`
id: demo
info:
  name: Demo
http:
- method: GET
  path:
  - '{{BaseURL}}/'
  matchers:
  - type: favicon
    hash:
    - 715c49c5512d763084a4082c27d935e1
  - type: regex
    regex:
    - (?mi)<title[^>]*>nginx ui.*?</title>
`))
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	rules, dm, _ := tpl.Rules()
	if dm != 0 {
		t.Errorf("DroppedMatchers = %d, want 0", dm)
	}
	ms := rules[0].Matchers
	if len(ms) != 2 {
		t.Fatalf("matchers = %d, want 2", len(ms))
	}
	if ms[0].Type != fingerprint.MatcherFavicon || ms[0].Value[0] != "715c49c5512d763084a4082c27d935e1" {
		t.Errorf("favicon matcher = %+v", ms[0])
	}
	if ms[1].Type != fingerprint.MatcherRegex || !strings.Contains(ms[1].Value[0], "nginx ui") {
		t.Errorf("regex matcher = %+v", ms[1])
	}
}

func TestParseTemplateHeaderPart(t *testing.T) {
	tpl, err := ParseTemplate([]byte(`
id: demo
info:
  name: Demo
http:
- path:
  - '{{BaseURL}}/'
  matchers:
  - type: word
    part: header
    words:
    - "X-Powered-By: PHP"
`))
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	rules, _, _ := tpl.Rules()
	if len(rules) != 1 || len(rules[0].Matchers) != 1 {
		t.Fatalf("rules = %+v", rules)
	}
	m := rules[0].Matchers[0]
	if !m.IsHeader() {
		t.Errorf("part = %q, want header", m.Part)
	}
	if m.Value[0] != "X-Powered-By: PHP" {
		t.Errorf("words = %v", m.Value)
	}
}

func TestUnquotedColonInWordsIsRejected(t *testing.T) {
	// 未加引号的 "X-Powered-By: PHP" 在 YAML 里是 map，解码到 []string 会失败。
	// 这类模板应被记为解析失败而不是静默产生错误的词表。
	if _, err := ParseTemplate([]byte(`
id: demo
info: {name: Demo}
http:
- path: ['{{BaseURL}}/']
  matchers:
  - type: word
    words:
    - X-Powered-By: PHP
`)); err == nil {
		t.Error("err = nil, want 解析失败（应当被统计为错误而非静默丢词）")
	}
}

func TestParseTemplateConditionAndPreserved(t *testing.T) {
	tpl, _ := ParseTemplate([]byte(`
id: demo
info:
  name: Demo
http:
- path:
  - '{{BaseURL}}/'
  matchers:
  - type: word
    condition: and
    words:
    - alpha
    - beta
`))
	rules, _, _ := tpl.Rules()
	if got := rules[0].Matchers[0].Condition(); got != fingerprint.CondAnd {
		t.Errorf("condition = %q, want and", got)
	}
}

func TestUnsupportedMatchersDropped(t *testing.T) {
	tpl, _ := ParseTemplate([]byte(`
id: complex
info:
  name: Complex
http:
- path:
  - '{{BaseURL}}/'
  matchers:
  - type: dsl
    dsl:
    - status_code == 200
  - type: word
    status: [200]
    words:
    - keep
  - type: word
    words:
    - ok
`))
	rules, dm, _ := tpl.Rules()
	if dm != 2 {
		t.Errorf("DroppedMatchers = %d, want 2（dsl 与带 status 的 matcher）", dm)
	}
	if len(rules) != 1 || len(rules[0].Matchers) != 1 {
		t.Fatalf("rules = %+v, want 仅保留一条 word matcher", rules)
	}
	if rules[0].Matchers[0].Value[0] != "ok" {
		t.Errorf("保留的 matcher = %+v", rules[0].Matchers[0])
	}
}

func TestTemplateWithOnlyUnsupportedMatchersIsDropped(t *testing.T) {
	tpl, _ := ParseTemplate([]byte(`
id: allbad
info:
  name: AllBad
http:
- path:
  - '{{BaseURL}}/'
  matchers:
  - type: dsl
    dsl:
    - status_code == 200
`))
	rules, dm, dr := tpl.Rules()
	if len(rules) != 0 {
		t.Errorf("rules = %+v, want 空", rules)
	}
	if dm != 1 || dr != 1 {
		t.Errorf("dropped = %d/%d, want 1/1", dm, dr)
	}
}

func TestTemplatedPathsAreDropped(t *testing.T) {
	tpl, _ := ParseTemplate([]byte(`
id: tmpl
info:
  name: Tmpl
http:
- path:
  - '{{RootURL}}/admin'
  - '{{Hostname}}/login'
  matchers:
  - type: word
    words:
    - x
`))
	rules, _, dr := tpl.Rules()
	if len(rules) != 0 || dr != 1 {
		t.Errorf("rules=%v droppedRules=%d, want 空/1（含变量路径无法静态化）", rules, dr)
	}
}

func TestPathNormalizationVariants(t *testing.T) {
	tpl, _ := ParseTemplate([]byte(`
id: paths
info:
  name: Paths
http:
- path:
  - '{{BaseURL}}'
  - '{{BaseURL}}/a/b?x=1'
  - 'https://example.com/c/d#frag'
  - /rel
  - '{{BaseURL}}/a/b?x=1'
  matchers:
  - type: word
    words:
    - x
`))
	rules, _, _ := tpl.Rules()
	want := []string{"/", "/a/b", "/c/d", "/rel"}
	got := rules[0].Paths
	if len(got) != len(want) {
		t.Fatalf("Paths = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Paths[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestMultiHTTPBlockGetsUniqueIDs(t *testing.T) {
	tpl, _ := ParseTemplate([]byte(`
id: multi
info:
  name: Multi
http:
- path:
  - '{{BaseURL}}/one'
  matchers:
  - type: word
    words: [a]
- path:
  - '{{BaseURL}}/two'
  matchers:
  - type: word
    words: [b]
`))
	rules, _, _ := tpl.Rules()
	if len(rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(rules))
	}
	if rules[0].ID == rules[1].ID {
		t.Errorf("ID 重复: %q", rules[0].ID)
	}
}

func TestConvertFSSkipsBadAndDedupesSorts(t *testing.T) {
	fsys := fstest.MapFS{
		"b.yaml": &fstest.MapFile{Data: []byte(`
id: zzz
info: {name: Z}
http:
- path: ['{{BaseURL}}/']
  matchers:
  - type: word
    words: [z]
`)},
		"a.yaml": &fstest.MapFile{Data: []byte(`
id: aaa
info: {name: A}
http:
- path: ['{{BaseURL}}/']
  matchers:
  - type: word
    words: [a]
`)},
		"broken.yaml": &fstest.MapFile{Data: []byte("::: not yaml :::\n\t- [")},
		"readme.txt":  &fstest.MapFile{Data: []byte("ignored")},
	}

	lib, st, err := ConvertFS(fsys, "test")
	if err != nil {
		t.Fatalf("ConvertFS: %v", err)
	}
	if st.Files != 3 {
		t.Errorf("Files = %d, want 3（仅 yaml 计入）", st.Files)
	}
	if len(st.Errors) != 1 {
		t.Errorf("Errors = %v, want 1 条（broken.yaml）", st.Errors)
	}
	if lib.Count != 2 || len(lib.Rules) != 2 {
		t.Fatalf("Count = %d, want 2", lib.Count)
	}
	if lib.Rules[0].ID != "aaa" || lib.Rules[1].ID != "zzz" {
		t.Errorf("规则未按 ID 排序: %s, %s", lib.Rules[0].ID, lib.Rules[1].ID)
	}
	if lib.Source != "test" {
		t.Errorf("Source = %q", lib.Source)
	}
}

func TestMarshalLibraryCompactAndRoundTrips(t *testing.T) {
	lib := &fingerprint.Library{
		GeneratedAt: "2026-09-10T00:00:00Z",
		Source:      "test",
		Count:       1,
		Rules: []fingerprint.Rule{{
			ID:    "x",
			Name:  "X",
			Paths: []string{"/"},
			Matchers: []fingerprint.Matcher{
				{Type: fingerprint.MatcherWord, Value: []string{"hi"}, CI: true},
			},
		}},
	}
	b, err := MarshalLibrary(lib)
	if err != nil {
		t.Fatalf("MarshalLibrary: %v", err)
	}
	if strings.Contains(string(b), "\n\t") || strings.Count(string(b), "\n") != 1 {
		t.Errorf("期望单行紧凑 JSON，实际:\n%s", b)
	}
	var back fingerprint.Library
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("回读失败: %v", err)
	}
	if back.Count != 1 || back.Rules[0].Matchers[0].CI != true {
		t.Errorf("回读结果 = %+v", back)
	}
}

func TestFallbackIDComesFromName(t *testing.T) {
	tpl, _ := ParseTemplate([]byte(`
info:
  name: OnlyName
http:
- path: ['{{BaseURL}}/']
  matchers:
  - type: word
    words: [x]
`))
	rules, _, _ := tpl.Rules()
	if len(rules) != 1 || rules[0].ID != "OnlyName" {
		t.Fatalf("rules = %+v, want ID 回退为 name", rules)
	}
}
