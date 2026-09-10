package fingerprint

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/einmsrf/scanner/pkg/httpx"
)

// 引擎默认上限。
const (
	DefaultMaxSubdirs    = 5  // 子目录候选数（DESIGN.md 第 5.2 节第 3 层）
	DefaultMaxPathProbes = 60 // 路径型规则最多发起的请求数
	DefaultMaxBaseProbes = 8  // 子目录 base 最多探测数
	evidenceMaxLen       = 120
)

// Input 是一次指纹识别所需的输入，由调用方（CLI）从 target.Site 组装。
// 这样设计使引擎不依赖 target 包，便于测试。
type Input struct {
	Origin string // scheme://host[:port]
	// Root 是请求 origin+"/" 得到的响应；nil 时引擎自行请求。
	// 它承载 DESIGN.md 第 5.2 节第 1 层（重定向跟随后的落地页）。
	Root *httpx.Response
	// Pages 是其它落地页（例如 base-path 命中的页面），仅用于抽取子目录候选。
	Pages []*httpx.Response
	// BasePaths 是候选 base 前缀（一般来自 target.Site.CandidateBases）。
	BasePaths []string
	// ManualBasePath 是 --base-path 手动指定的 base，优先级最高。
	ManualBasePath string
}

// Options 控制单次识别的开销上限。
type Options struct {
	MaxSubdirs    int  // 子目录候选数，0 取默认
	MaxPathProbes int  // 路径型规则最多发起的请求数，0 取默认
	MaxBaseProbes int  // 子目录 base 最多探测数，0 取默认
	SkipRootMatch bool // 跳过落地页的路径无关规则匹配（默认不跳过）
}

func (o Options) withDefaults() Options {
	if o.MaxSubdirs <= 0 {
		o.MaxSubdirs = DefaultMaxSubdirs
	}
	if o.MaxPathProbes <= 0 {
		o.MaxPathProbes = DefaultMaxPathProbes
	}
	if o.MaxBaseProbes <= 0 {
		o.MaxBaseProbes = DefaultMaxBaseProbes
	}
	return o
}

// Match 是一条命中的指纹。
type Match struct {
	Rule     *Rule
	Path     string // 规则里的相对路径（"/" 表示路径无关）
	URL      string // 实际判定所用的 URL
	Via      string // landing | path | favicon
	Evidence string // 命中的关键字/正则/favicon 哈希等依据
}

// Result 是一次指纹识别的结果。
type Result struct {
	Matches   []Match
	Probed    []string // 实际请求过的 URL（含根与 favicon）
	Requests  int
	Truncated bool // 因请求上限提前停止路径探测
	Notes     []string
}

// Rules 返回命中的规则指针列表。
func (r *Result) Rules() []*Rule {
	out := make([]*Rule, 0, len(r.Matches))
	for i := range r.Matches {
		out = append(out, r.Matches[i].Rule)
	}
	return out
}

// Products 返回去重后的产品名列表（按首次命中顺序）。
func (r *Result) Products() []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range r.Matches {
		p := m.Rule.ProductOrName()
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// Engine 是编译好正则与索引的指纹匹配引擎，可安全并发复用。
type Engine struct {
	lib      *Library
	rules    []compiledRule
	rootIdx  []int            // 只含 "/" 路径的规则（路径无关，直接匹配落地页）
	iconIdx  []int            // 含 favicon matcher 的规则
	pathIdx  map[string][]int // 非根路径 → 规则下标
	pathRank []string         // 非根路径按引用规则数降序（提高命中效率）

	RegexSkipped int // 因正则无法编译而被跳过的 matcher 数
}

type compiledMatcher struct {
	m  Matcher
	re []*regexp.Regexp
}

type compiledRule struct {
	rule     Rule
	matchers []compiledMatcher
}

// NewEngine 建立索引并预编译全部正则。
func NewEngine(lib *Library) *Engine {
	e := &Engine{lib: lib, pathIdx: map[string][]int{}}
	counts := map[string]int{}

	for i := range lib.Rules {
		r := lib.Rules[i]
		cr := compiledRule{rule: r}
		hasFavicon := false
		compiled := 0
		for _, m := range r.Matchers {
			cm := compiledMatcher{m: m}
			if m.Type == MatcherFavicon {
				hasFavicon = true
			}
			if m.Type == MatcherRegex {
				for _, expr := range m.Value {
					pat := expr
					if m.CI {
						pat = "(?i)" + pat
					}
					re, err := regexp.Compile(pat)
					if err != nil {
						e.RegexSkipped++
						continue
					}
					cm.re = append(cm.re, re)
				}
				if len(cm.re) == 0 {
					continue // 该 matcher 全部正则无效 → 视为不可用
				}
			}
			cr.matchers = append(cr.matchers, cm)
			compiled++
		}
		if compiled == 0 {
			continue // 规则内没有可用的 matcher，跳过整条规则
		}
		idx := len(e.rules)
		e.rules = append(e.rules, cr)

		if hasFavicon {
			e.iconIdx = append(e.iconIdx, idx)
		}
		// 含 "/" 的规则额外享受一次“免费”的落地页匹配：根响应已经拿到，
		// 不必再发请求（DESIGN.md 第 5.2 节第 2 层“路径无关规则”）。
		hasRootPath := len(r.Paths) == 0
		for _, p := range r.Paths {
			if p == "/" || p == "" {
				hasRootPath = true
				continue
			}
			e.pathIdx[p] = append(e.pathIdx[p], idx)
			counts[p]++
		}
		if hasRootPath {
			e.rootIdx = append(e.rootIdx, idx)
		}
	}

	// 路径按“能解锁多少条规则”降序，同级按字典序保证稳定。
	e.pathRank = make([]string, 0, len(counts))
	for p := range counts {
		e.pathRank = append(e.pathRank, p)
	}
	sort.Slice(e.pathRank, func(i, j int) bool {
		if counts[e.pathRank[i]] != counts[e.pathRank[j]] {
			return counts[e.pathRank[i]] > counts[e.pathRank[j]]
		}
		return e.pathRank[i] < e.pathRank[j]
	})
	return e
}

// Library 返回引擎使用的指纹库。
func (e *Engine) Library() *Library { return e.lib }

// RuleCount 返回可用规则数。
func (e *Engine) RuleCount() int { return len(e.rules) }

// PathCount 返回需要探测的不同路径数。
func (e *Engine) PathCount() int { return len(e.pathRank) }

// Scan 对单个站点执行四层兜底指纹识别。
func (e *Engine) Scan(ctx context.Context, c *httpx.Client, in Input, opts Options) (*Result, error) {
	opts = opts.withDefaults()
	if in.Origin == "" {
		return nil, fmt.Errorf("fingerprint: Input.Origin 为空")
	}
	res := &Result{}
	origin := strings.TrimSuffix(in.Origin, "/")

	// 第 1 层：根路径响应（跟随重定向后的落地页）。
	root := in.Root
	if root == nil {
		resp, err := c.Get(ctx, origin+"/")
		res.Requests++
		if err != nil {
			res.Notes = append(res.Notes, "根路径请求失败: "+err.Error())
		} else {
			root = resp
			res.Probed = append(res.Probed, resp.URL)
		}
	}

	pages := make([]*httpx.Response, 0, len(in.Pages)+1)
	if root != nil {
		pages = append(pages, root)
	}
	for _, p := range in.Pages {
		if p != nil && p != root {
			pages = append(pages, p)
		}
	}

	matched := map[string]bool{}
	add := func(r *Rule, m Match) {
		if matched[r.ID] {
			return
		}
		matched[r.ID] = true
		m.Rule = r
		res.Matches = append(res.Matches, m)
	}

	// 第 2 层之一：路径无关规则直接匹配落地页。
	if root != nil && !opts.SkipRootMatch {
		for _, i := range e.rootIdx {
			cr := &e.rules[i]
			if hit, ev := cr.match(root, nil); hit {
				add(&cr.rule, Match{Path: "/", URL: root.URL, Via: "landing", Evidence: ev})
			}
		}
	}

	// 第 2 层之二：favicon（解析 <link rel="icon"> 拿真实位置）。
	if root != nil && len(e.iconIdx) > 0 {
		if icon := e.fetchIcon(ctx, c, origin, root, res); len(icon) > 0 {
			for _, i := range e.iconIdx {
				cr := &e.rules[i]
				if hit, ev := cr.match(root, icon); hit {
					add(&cr.rule, Match{Path: "/", URL: root.URL, Via: "favicon", Evidence: ev})
				}
			}
		}
	}

	// 第 3、4 层：候选 base × 规则路径。
	bases := e.candidateBases(in, pages, opts)
	cache := map[string]*httpx.Response{}
	if root != nil {
		cache[root.URL] = root
	}

	// 第 3 层（对根路径型规则）：把 base "/" 换成候选子目录再试一次。
	// 上游指纹库 3373 条规则里 3370 条都以 "/" 为路径，因此这一步是
	// “部署目录被修改”场景下的主要兜底手段。
	baseProbes := 0
	for _, base := range bases {
		if base == "" {
			continue // 根已处理
		}
		if baseProbes >= opts.MaxBaseProbes || c.Remaining() <= 0 {
			res.Truncated = true
			break
		}
		u := origin + base + "/"
		resp := cache[u]
		if resp == nil {
			r, err := c.Get(ctx, u)
			baseProbes++
			res.Requests++
			if err != nil {
				continue
			}
			resp = r
			cache[u] = resp
			res.Probed = append(res.Probed, resp.URL)
		}
		for _, i := range e.rootIdx {
			cr := &e.rules[i]
			if hit, ev := cr.match(resp, nil); hit {
				add(&cr.rule, Match{Path: "/", URL: resp.URL, Via: "subdir", Evidence: ev})
			}
		}
	}

	probes := 0

	for _, p := range e.pathRank {
		if probes >= opts.MaxPathProbes {
			res.Truncated = true
			res.Notes = append(res.Notes, fmt.Sprintf("路径探测达到上限 %d，%d 条路径未探测", opts.MaxPathProbes, len(e.pathRank)-probes))
			break
		}
		idxList := e.pathIdx[p]
		for _, base := range bases {
			if probes >= opts.MaxPathProbes {
				res.Truncated = true
				break
			}
			u := origin + joinPath(base, p)
			resp := cache[u]
			if resp == nil {
				r, err := c.Get(ctx, u)
				probes++
				res.Requests++
				if err != nil {
					continue
				}
				resp = r
				cache[u] = resp
				res.Probed = append(res.Probed, resp.URL)
			}
			hitHere := false
			for _, i := range idxList {
				cr := &e.rules[i]
				if hit, ev := cr.match(resp, nil); hit {
					add(&cr.rule, Match{Path: p, URL: resp.URL, Via: "path", Evidence: ev})
					hitHere = true
				}
			}
			// 该 base 已命中，说明找到了正确的部署目录，无需再试其它 base。
			if hitHere {
				break
			}
		}
	}

	sort.SliceStable(res.Matches, func(i, j int) bool {
		return res.Matches[i].Rule.ProductOrName() < res.Matches[j].Rule.ProductOrName()
	})
	return res, nil
}

// candidateBases 组装候选 base 前缀，按优先级排列：
// 手动指定 → 落地页/请求路径推出的候选 → HTML/JS 抽取的一级目录 Top N → 站点根。
func (e *Engine) candidateBases(in Input, pages []*httpx.Response, opts Options) []string {
	var out []string
	seen := map[string]bool{}
	add := func(b string) {
		b = normalizeBase(b)
		if seen[b] {
			return
		}
		seen[b] = true
		out = append(out, b)
	}
	add(in.ManualBasePath)
	for _, b := range in.BasePaths {
		add(b)
	}
	for _, b := range ExtractSubdirs(pages, opts.MaxSubdirs) {
		add(b)
	}
	add("/")
	return out
}

// normalizeBase 把 base 规范成 ""（根）或 "/seg" 形式。
func normalizeBase(b string) string {
	b = strings.TrimSpace(b)
	if b == "" || b == "/" {
		return ""
	}
	if !strings.HasPrefix(b, "/") {
		b = "/" + b
	}
	return strings.TrimSuffix(b, "/")
}

// joinPath 把 base 与规则路径拼成完整路径。
func joinPath(base, p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return normalizeBase(base) + p
}

// fetchIcon 取 favicon 原始字节：优先 HTML 里声明的图标，失败再退回 /favicon.ico。
func (e *Engine) fetchIcon(ctx context.Context, c *httpx.Client, origin string, root *httpx.Response, res *Result) []byte {
	candidates := []string{FindIconURL(origin, root)}
	if fallback := origin + "/favicon.ico"; candidates[0] != fallback {
		candidates = append(candidates, fallback)
	}
	for _, u := range candidates {
		resp, err := c.Get(ctx, u)
		res.Requests++
		if err != nil {
			continue
		}
		res.Probed = append(res.Probed, resp.URL)
		if resp.Status < 400 && len(resp.Body) > 0 {
			return resp.Body
		}
	}
	return nil
}

// match 判断规则是否命中给定响应。icon 为 nil 时 favicon matcher 无法评估。
func (cr *compiledRule) match(resp *httpx.Response, icon []byte) (bool, string) {
	if resp == nil {
		return false, ""
	}
	and := cr.rule.RuleCondition() == CondAnd
	if and {
		var evs []string
		for i := range cr.matchers {
			hit, ev, evaluable := cr.matchers[i].match(resp, icon)
			if !evaluable || !hit {
				return false, ""
			}
			evs = append(evs, ev)
		}
		return true, strings.Join(evs, " & ")
	}
	for i := range cr.matchers {
		if hit, ev, _ := cr.matchers[i].match(resp, icon); hit {
			return true, ev
		}
	}
	return false, ""
}

// match 判断单个 matcher。返回是否命中、依据、以及能否评估。
func (cm *compiledMatcher) match(resp *httpx.Response, icon []byte) (hit bool, evidence string, evaluable bool) {
	switch cm.m.Type {
	case MatcherFavicon:
		if len(icon) == 0 {
			return false, "", false
		}
		for _, h := range cm.m.Value {
			if FaviconMatches([]string{h}, icon) {
				return true, "favicon:" + h, true
			}
		}
		return false, "", true

	case MatcherWord:
		text := cm.target(resp)
		if text == "" {
			return false, "", true
		}
		if cm.m.CI {
			text = strings.ToLower(text)
		}
		and := cm.m.Condition() == CondAnd
		var found []string
		for _, w := range cm.m.Value {
			needle := w
			if cm.m.CI {
				needle = strings.ToLower(w)
			}
			if strings.Contains(text, needle) {
				found = append(found, w)
			} else if and {
				return false, "", true
			}
		}
		if len(found) == 0 {
			return false, "", true
		}
		return true, "word:" + clip(found[0]), true

	case MatcherRegex:
		text := cm.target(resp)
		if text == "" {
			return false, "", true
		}
		and := cm.m.Condition() == CondAnd
		var found []string
		for _, re := range cm.re {
			loc := re.FindStringIndex(text)
			if loc != nil {
				found = append(found, clip(text[loc[0]:loc[1]]))
			} else if and {
				return false, "", true
			}
		}
		if len(found) == 0 {
			return false, "", true
		}
		return true, "regex:" + found[0], true
	}
	return false, "", false
}

// target 返回 matcher 作用的目标文本（响应体或响应头）。
func (cm *compiledMatcher) target(resp *httpx.Response) string {
	if cm.m.IsHeader() {
		return headerText(resp)
	}
	return resp.Text()
}

// headerText 把响应头序列化成 "Key: Value" 行，键排序保证结果稳定。
func headerText(resp *httpx.Response) string {
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		for _, v := range resp.Header[k] {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// clip 截断过长的证据串并压成单行。
func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) > evidenceMaxLen {
		r := []rune(s)
		return string(r[:evidenceMaxLen]) + "…"
	}
	return s
}
