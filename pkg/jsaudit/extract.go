package jsaudit

import (
	"fmt"
	"sort"
	"strings"
)

// 默认上限。
const (
	DefaultMaxEndpoints = 300
	DefaultMaxFindings  = 500
	DefaultContextChars = 50
)

// Finding 是一条检测结果。
type Finding struct {
	Category Category
	Severity Severity
	RuleID   string
	File     string // JS 文件 URL，或内联脚本所属页面
	Source   string // external | inline | sourcemap
	Line     int    // 1-based
	Match    string // 命中的原文片段（截断）
	Value    string // 敏感值（未解码时等于命中值）
	Decoded  string // base64 / JWT 解码结果，空表示无
	Context  string // 敏感值前后各 ContextChars 字符（供语义层）
	Entropy  float64
	Note     string
}

// Endpoint 是从 JS 中提取到的接口路径。
type Endpoint struct {
	Path  string
	Count int
}

// Stats 记录过滤情况，便于评估规则质量。
type Stats struct {
	RawMatches          int // 规则原始命中数
	FilteredPlaceholder int // 因占位符被过滤
	FilteredTooShort    int // 因长度不足被过滤
	FilteredLowEntropy  int // 因熵值不足被过滤
	DedupedFindings     int // 因重复被合并
	TruncatedFindings   int // 因上限被截断
}

// ExtractOptions 控制提取行为。
type ExtractOptions struct {
	MaxEndpoints  int
	MaxFindings   int
	ContextChars  int
	SkipEndpoints bool // 不提取接口路径
}

func (o ExtractOptions) withDefaults() ExtractOptions {
	if o.MaxEndpoints <= 0 {
		o.MaxEndpoints = DefaultMaxEndpoints
	}
	if o.MaxFindings <= 0 {
		o.MaxFindings = DefaultMaxFindings
	}
	if o.ContextChars <= 0 {
		o.ContextChars = DefaultContextChars
	}
	return o
}

// Result 是一次提取结果。
type Result struct {
	Findings  []Finding
	Endpoints []Endpoint
	Stats     Stats
}

// Extract 对收集到的 JS 资源执行七类规则提取。
func Extract(assets []Asset, opts ExtractOptions) *Result {
	opts = opts.withDefaults()
	res := &Result{}
	seen := map[string]bool{}
	endpointCount := map[string]int{}

	for _, a := range assets {
		if len(a.Code) == 0 {
			continue
		}
		code := string(a.Code)

		// 七类规则（注释类只作用于注释文本，由 extractComments 单独处理）
		for _, cr := range compiledRules {
			if cr.spec.Category == CatComment {
				continue
			}
			for _, loc := range cr.re.FindAllStringSubmatchIndex(code, -1) {
				if len(loc) < 2 {
					continue
				}
				res.Stats.RawMatches++
				matchStart, matchEnd := loc[0], loc[1]
				valStart, valEnd := matchStart, matchEnd
				if cr.spec.ValueGroup > 0 && len(loc) > cr.spec.ValueGroup*2+1 {
					gs, ge := loc[cr.spec.ValueGroup*2], loc[cr.spec.ValueGroup*2+1]
					if gs >= 0 && ge > gs {
						valStart, valEnd = gs, ge
					}
				}
				value := code[valStart:valEnd]

				f, ok := buildFinding(cr, value, code, a, matchStart, valStart, opts)
				if !ok {
					switch {
					case len(value) < cr.spec.MinLen:
						res.Stats.FilteredTooShort++
					case !cr.spec.HighConfidence && IsPlaceholder(value):
						res.Stats.FilteredPlaceholder++
					default:
						res.Stats.FilteredLowEntropy++
					}
					continue
				}
				key := fmt.Sprintf("%s|%s|%s", f.Category, f.File, f.Value)
				if seen[key] {
					res.Stats.DedupedFindings++
					continue
				}
				seen[key] = true
				if len(res.Findings) >= opts.MaxFindings {
					res.Stats.TruncatedFindings++
					continue
				}
				res.Findings = append(res.Findings, *f)
			}
		}

		// 注释中的敏感信息（测试账号）+ 注释中的地址
		for _, f := range extractComments(code, a, opts) {
			key := fmt.Sprintf("%s|%s|%s", f.Category, f.File, f.Value)
			if seen[key] {
				res.Stats.DedupedFindings++
				continue
			}
			seen[key] = true
			if len(res.Findings) >= opts.MaxFindings {
				res.Stats.TruncatedFindings++
				continue
			}
			res.Findings = append(res.Findings, f)
		}

		// 接口路径（只提取，绝不请求）
		if !opts.SkipEndpoints {
			// 多个正则可能命中同一处（如 fetch("/api/x") 同时被 relPathRe 与
			// callPathRe 匹配），按 (路径, 偏移) 去重后再计数，避免重复计数。
			seenHit := map[string]bool{}
			for _, h := range extractPaths(code) {
				key := fmt.Sprintf("%s@%d", h.path, h.off)
				if seenHit[key] {
					continue
				}
				seenHit[key] = true
				endpointCount[h.path]++
			}
		}
	}

	res.Endpoints = rankEndpoints(endpointCount, opts.MaxEndpoints)
	sortFindings(res.Findings)
	return res
}

// buildFinding 组装一条命中，含过滤判定与解码。
//
// 占位符过滤只作用于“靠键名/熵值猜测”的规则；AKIA…、-----BEGIN PRIVATE KEY-----、
// JWT、Authorization 头这类形态唯一的规则不做占位符过滤——它们的形态本身就是证据，
// 且真实值里也可能出现 example 之类的字样。
func buildFinding(cr compiledRule, value, code string, a Asset, matchStart, valStart int, opts ExtractOptions) (*Finding, bool) {
	if len(value) < cr.spec.MinLen {
		return nil, false
	}
	if !cr.spec.HighConfidence && IsPlaceholder(value) {
		return nil, false
	}
	if e := cr.spec.minEntropy(); e > 0 && Entropy(value) < e {
		return nil, false
	}

	f := &Finding{
		Category: cr.spec.Category,
		Severity: cr.spec.Severity,
		RuleID:   cr.spec.ID,
		File:     a.URL,
		Source:   a.Source,
		Line:     lineOf(code, matchStart),
		Match:    clip(strings.TrimSpace(runeRange(code, matchStart, matchStart+200)), 160),
		Value:    clip(strings.TrimSpace(value), 160),
		Entropy:  Entropy(value),
		Note:     cr.spec.Hint,
	}
	f.Context = contextAround(code, valStart, valStart+len(value), opts.ContextChars)

	switch {
	case cr.spec.DecodeBase64:
		if decoded, depth := DecodeBase64Nested(value, MaxBase64Depth); depth > 0 {
			f.Decoded = clip(decoded, 200)
			if CredentialLike(decoded) {
				f.Note = fmt.Sprintf("%s；已解码为 `user:pass` 形式（嵌套 %d 层）", cr.spec.Hint, depth)
			} else {
				f.Note = fmt.Sprintf("%s；已解码（嵌套 %d 层）", cr.spec.Hint, depth)
			}
		}
	case cr.spec.DecodeJWT:
		if h, p, ok := DecodeJWT(value); ok {
			f.Decoded = clip("header="+h+" payload="+p, 400)
			f.Note = cr.spec.Hint
		}
	}
	return f, true
}

// extractComments 提取注释里的测试账号与文档/内网地址。
func extractComments(code string, a Asset, opts ExtractOptions) []Finding {
	var out []Finding
	add := func(hit string, offset int, note, ruleID string) {
		v := strings.TrimSpace(hit)
		if v == "" || IsPlaceholder(v) {
			return
		}
		out = append(out, Finding{
			Category: CatComment,
			Severity: SevLow,
			RuleID:   ruleID,
			File:     a.URL,
			Source:   a.Source,
			Line:     lineOf(code, offset),
			Match:    clip(v, 160),
			Value:    clip(v, 160),
			Context:  contextAround(code, offset, offset+len(hit), opts.ContextChars),
			Entropy:  Entropy(v),
			Note:     note,
		})
	}

	for _, loc := range blockCommentRe.FindAllStringIndex(code, -1) {
		body := code[loc[0]:loc[1]]
		collectCommentHits(body, loc[0], code, add)
	}
	for _, m := range lineCommentRe.FindAllStringSubmatchIndex(code, -1) {
		if len(m) < 4 || m[2] < 0 {
			continue
		}
		body := code[m[2]:m[3]]
		collectCommentHits(body, m[2], code, add)
	}
	return out
}

// collectCommentHits 在单条注释文本里找敏感信息。
func collectCommentHits(body string, base int, code string, add func(string, int, string, string)) {
	for _, cr := range compiledRules {
		if cr.spec.Category != CatComment {
			continue
		}
		for _, loc := range cr.re.FindAllStringSubmatchIndex(body, -1) {
			hit := body[loc[0]:loc[1]]
			add(hit, base+loc[0], cr.spec.Hint, cr.spec.ID)
		}
	}
	// 注释里的地址（常为内部文档/后台地址）
	for _, loc := range commentURLRe.FindAllStringIndex(body, -1) {
		u := body[loc[0]:loc[1]]
		if isStaticURL(u) {
			continue
		}
		add(u, base+loc[0], "注释中的地址（可能是内部文档/后台入口）", "comment-url")
	}
}

// pathHit 是一次路径命中及其在代码中的偏移（用于跨正则去重）。
type pathHit struct {
	path string
	off  int
}

// extractPaths 提取 JS 里的接口路径与绝对 URL。
func extractPaths(code string) []pathHit {
	// 处理 \/\/static/... 这类被转义的畸形写法，便于统一提取。
	norm := strings.ReplaceAll(code, `\/`, "/")
	var out []pathHit
	addPath := func(p string, off int) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if isStaticURL(p) || isNoisePath(p) {
			return
		}
		out = append(out, pathHit{path: p, off: off})
	}
	for _, m := range absURLRe.FindAllStringSubmatchIndex(norm, -1) {
		if len(m) >= 4 && m[2] >= 0 {
			addPath(norm[m[2]:m[3]], m[2])
		}
	}
	for _, m := range relPathRe.FindAllStringSubmatchIndex(norm, -1) {
		if len(m) >= 4 && m[2] >= 0 {
			addPath(norm[m[2]:m[3]], m[2])
		}
	}
	for _, m := range callPathRe.FindAllStringSubmatchIndex(norm, -1) {
		if len(m) >= 4 && m[2] >= 0 {
			addPath(norm[m[2]:m[3]], m[2])
		}
	}
	return out
}

// rankEndpoints 去重、按出现次数降序（同级按路径字典序）排序并截断。
func rankEndpoints(counts map[string]int, max int) []Endpoint {
	list := make([]Endpoint, 0, len(counts))
	for p, c := range counts {
		list = append(list, Endpoint{Path: p, Count: c})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Count != list[j].Count {
			return list[i].Count > list[j].Count
		}
		return list[i].Path < list[j].Path
	})
	if max > 0 && len(list) > max {
		list = list[:max]
	}
	return list
}

// sortFindings 高危优先，其次类别、文件、行号。
func sortFindings(fs []Finding) {
	rank := func(s Severity) int {
		switch s {
		case SevHigh:
			return 0
		case SevMedium:
			return 1
		case SevLow:
			return 2
		default:
			return 3
		}
	}
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if rank(a.Severity) != rank(b.Severity) {
			return rank(a.Severity) < rank(b.Severity)
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
}

// contextAround 返回敏感值前后各 n 个字符，压成单行。
// 按 UTF-8 字符边界对齐，避免把多字节汉字切成半个导致报告里出现非法编码。
func contextAround(code string, start, end, n int) string {
	return clip(runeRange(code, start-n, end+n), n*2+240)
}

// isContinuation 判断是否为 UTF-8 续字节。
func isContinuation(b byte) bool { return b&0xC0 == 0x80 }

// runeRange 返回 s[lo:hi]，并把两端收缩到 UTF-8 字符边界，
// 保证结果一定是合法 UTF-8（目标站点常见 GBK/乱码字节，直接按字节切会切坏字符）。
func runeRange(s string, lo, hi int) string {
	if lo < 0 {
		lo = 0
	}
	if hi > len(s) {
		hi = len(s)
	}
	if lo >= hi {
		return ""
	}
	for lo < hi && isContinuation(s[lo]) {
		lo++
	}
	for hi > lo && isContinuation(s[hi-1]) {
		hi--
	}
	return s[lo:hi]
}

// clip 压成单行并截断。始终返回合法 UTF-8：
// []rune 转换会把非法字节规整为 U+FFFD，因此这里统一用 string(r) 而非原串。
func clip(s string, max int) string {
	r := []rune(strings.Join(strings.Fields(s), " "))
	if len(r) > max {
		return string(r[:max]) + "…"
	}
	return string(r)
}
