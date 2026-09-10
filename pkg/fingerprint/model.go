// Package fingerprint 定义指纹规则的数据模型、加载与匹配。
//
// 规则来源是 FingerprintHub 的 nuclei YAML 模板，经 pkg/convert 离线转换成本包的
// Library（紧凑 JSON）后 go:embed 进二进制。
package fingerprint

import "strings"

// Matcher 类型。
const (
	MatcherWord    = "word"
	MatcherRegex   = "regex"
	MatcherFavicon = "favicon"
)

// 匹配目标部位。
const (
	PartBody   = "body"
	PartHeader = "header"
)

// 多条匹配项之间的关系。
const (
	CondAnd = "and"
	CondOr  = "or"
)

// Library 是转换后的完整指纹库，也是 fingerprints.json 的顶层结构。
type Library struct {
	GeneratedAt string `json:"generated_at"`
	Source      string `json:"source"`
	Count       int    `json:"count"`
	Rules       []Rule `json:"rules"`
}

// Rule 是一条指纹规则。Paths 与 Matchers 组合判定：任一 path 的响应满足
// 任一 matcher 即命中（matchers 之间为 OR，与 nuclei 默认 matchers-condition 一致）。
type Rule struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Product  string    `json:"product,omitempty"`
	Vendor   string    `json:"vendor,omitempty"`
	Tags     []string  `json:"tags,omitempty"`
	Paths    []string  `json:"paths,omitempty"` // 相对路径，如 "/"、"/nacos/"
	Matchers []Matcher `json:"matchers"`
	Cond     string    `json:"cond,omitempty"` // matchers 之间关系，默认 or
}

// Matcher 是一条匹配项。Value 的含义随 Type 变化：
//
//	word    → 关键字列表
//	regex   → 正则列表
//	favicon → 哈希列表（32 位十六进制为 md5，纯数字为 mmh3 有符号整数）
type Matcher struct {
	Type  string   `json:"type"`
	Part  string   `json:"part,omitempty"` // 空/body 或 header
	Value []string `json:"value,omitempty"`
	CI    bool     `json:"ci,omitempty"`   // 关键字大小写不敏感
	Cond  string   `json:"cond,omitempty"` // 单个 matcher 内多项之间关系，默认 or
}

// Condition 返回 matcher 内多项之间的关系，缺省为 or。
func (m Matcher) Condition() string {
	if strings.EqualFold(m.Cond, CondAnd) {
		return CondAnd
	}
	return CondOr
}

// RuleCondition 返回 matchers 之间的关系，缺省为 or。
func (r Rule) RuleCondition() string {
	if strings.EqualFold(r.Cond, CondAnd) {
		return CondAnd
	}
	return CondOr
}

// IsHeader 判断该 matcher 作用于响应头。
func (m Matcher) IsHeader() bool { return strings.EqualFold(m.Part, PartHeader) }
