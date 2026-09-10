package jsaudit

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
)

// 真实数据的回归验证：拿 2026-09-10 晚 113 目标批量扫描的报告，把**新**的
// 端点/注释过滤规则重新跑一遍，确认
//
//	① 已知的脏数据全部被剔除；
//	② 合法的 REST 路径（含 : 与 * 参数）一个都没被误删。
//
// 报告位于 .cache/reports/（已 gitignore），CI 上不存在 → 自动跳过。
func loadRealBatchReport(t *testing.T) map[string]any {
	t.Helper()
	path := "../../.cache/reports/scan-20260910-231347.json"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("未找到批量扫描报告，跳过真实数据验证: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("解析报告失败: %v", err)
	}
	return doc
}

// collectBatch 汇总报告里的端点集合与注释 URL 列表。
func collectBatch(t *testing.T, doc map[string]any) (endpoints map[string]int, commentURLs map[string]string) {
	t.Helper()
	endpoints = map[string]int{}
	commentURLs = map[string]string{} // value -> 所在文件（用来推断主机名）
	targets, _ := doc["targets"].([]any)
	for _, ti := range targets {
		tm, ok := ti.(map[string]any)
		if !ok {
			continue
		}
		js, _ := tm["js"].(map[string]any)
		if js == nil {
			continue
		}
		if eps, ok := js["endpoints"].([]any); ok {
			for _, ei := range eps {
				if em, ok := ei.(map[string]any); ok {
					if p, ok := em["path"].(string); ok {
						endpoints[p]++
					}
				}
			}
		}
		if fs, ok := js["findings"].([]any); ok {
			for _, fi := range fs {
				fm, ok := fi.(map[string]any)
				if !ok {
					continue
				}
				if fm["rule_id"] != "comment-url" {
					continue
				}
				v, _ := fm["value"].(string)
				f, _ := fm["file"].(string)
				if v != "" {
					commentURLs[v] = f
				}
			}
		}
	}
	return endpoints, commentURLs
}

func TestRealBatchEndpointFiltering(t *testing.T) {
	doc := loadRealBatchReport(t)
	endpoints, _ := collectBatch(t, doc)

	// 已知脏数据必须全部被剔除
	knownGarbage := []string{
		"GET", "get", "HEAD", "POST", "post",
		"${e}", "/${filename}", "image/${e.type}",
		"/errorCorrectLevel:", "/:ids+.", "/groups/:groupName+",
		"//#line", "//.*?/", "../", "/./",
		"image/png", "image/jpeg", "image/svg+xml",
	}
	for _, p := range knownGarbage {
		if _, present := endpoints[p]; !present {
			continue // 该报告里没有这一条，跳过
		}
		if r := EndpointDropReason(p); r == "" {
			t.Errorf("脏数据 %q 未被剔除（应命中某条规则）", p)
		}
	}

	// 合法 REST 路径（含 : 与 *）必须保留
	knownLegit := []string{
		"/namespaces/:tenantNamespace/tenants/:tenantName/pods",
		"/buckets/:bucketName/admin*",
		"/video/record", "/video/stream",
	}
	var checked int
	for _, p := range knownLegit {
		if _, present := endpoints[p]; !present {
			continue
		}
		checked++
		if r := EndpointDropReason(p); r != "" {
			t.Errorf("合法端点 %q 被误删（原因 %s）", p, r)
		}
	}
	if checked == 0 {
		t.Log("报告中未出现预置的合法端点样本，仅做了脏数据检查")
	}

	// 全量统计：统计保留/剔除，并确保没有把带 : 或 * 的路径整类删掉
	var kept, dropped, paramKept, paramDropped int
	for p := range endpoints {
		hasParam := strings.ContainsAny(p, ":*")
		if EndpointDropReason(p) == "" {
			kept++
			if hasParam {
				paramKept++
			}
		} else {
			dropped++
			if hasParam {
				paramDropped++
			}
		}
	}
	t.Logf("真实数据端点去重 %d 个：保留 %d（其中带 :/* 的 %d），剔除 %d（其中带 :/* 的 %d）",
		len(endpoints), kept, paramKept, dropped, paramDropped)
	if paramKept < 50 {
		t.Errorf("带 :/* 的合法路径只保留了 %d 个，疑似被整类误删", paramKept)
	}
	if kept < len(endpoints)*80/100 {
		t.Errorf("保留率 %.0f%% 过低，疑似过度过滤", float64(kept)*100/float64(len(endpoints)))
	}
}

func TestRealBatchCommentURLFiltering(t *testing.T) {
	doc := loadRealBatchReport(t)
	_, commentURLs := collectBatch(t, doc)
	if len(commentURLs) == 0 {
		t.Skip("报告里没有 comment-url 发现")
	}

	// 已知噪声（w3.org 命名空间 / 库 license / 教程博客）必须被丢弃
	knownNoise := []string{
		"http://www.w3.org/2000/svg",
		"http://www.w3.org/1999/xhtml",
		"http://www.w3.org/1998/Math/MathML",
		"https://lodash.com/",
		"https://openjsf.org/",
		"http://underscorejs.org/LICENSE",
	}
	for _, n := range knownNoise {
		for v := range commentURLs {
			if strings.HasPrefix(v, n) {
				if CommentURLRelevant(v, hostOf(commentURLs[v])) {
					t.Errorf("公共文档域名噪声未被过滤: %q", v)
				}
			}
		}
	}

	kept, dropped := 0, 0
	for v, file := range commentURLs {
		if CommentURLRelevant(v, hostOf(file)) {
			kept++
			if kept <= 8 {
				t.Logf("保留: %s", v)
			}
		} else {
			dropped++
		}
	}
	rate := float64(dropped) * 100 / float64(kept+dropped)
	t.Logf("真实数据注释 URL %d 条：丢弃 %d、保留 %d，降噪率 %.1f%%", kept+dropped, dropped, kept, rate)
	if rate < 50 {
		t.Errorf("降噪率 %.1f%% 偏低，本次修复未达到预期效果", rate)
	}
}

// hostOf 已在 denoise.go 定义；此处的辅助仅用于测试可读性。
func hostName(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// 量化 vendor 过滤的真实效果：拿报告里 350 条发现的文件路径跑一遍
// 文件名级 vendor 判定，看有多少条会被"vendor 只跑高危规则"挡掉。
func TestRealBatchVendorSuppressionImpact(t *testing.T) {
	doc := loadRealBatchReport(t)
	targets, _ := doc["targets"].([]any)

	total, vendorHi, vendorSuppressed, nonVendor := 0, 0, 0, 0
	for _, ti := range targets {
		tm, ok := ti.(map[string]any)
		if !ok {
			continue
		}
		js, _ := tm["js"].(map[string]any)
		if js == nil {
			continue
		}
		fs, _ := js["findings"].([]any)
		for _, fi := range fs {
			fm, ok := fi.(map[string]any)
			if !ok {
				continue
			}
			total++
			file, _ := fm["file"].(string)
			sev, _ := fm["severity"].(string)
			if !IsVendorAsset(file, "") {
				nonVendor++
				continue
			}
			if sev == "high" {
				vendorHi++
			} else {
				vendorSuppressed++
			}
		}
	}
	if total == 0 {
		t.Skip("报告里没有发现记录")
	}
	pct := float64(vendorSuppressed) * 100 / float64(total)
	t.Logf("真实数据发现 %d 条：vendor 文件占 %d 条，其中被压制的低/中危 %d 条（%.1f%%），"+
		"vendor 内保留的高危 %d 条，非 vendor 文件 %d 条",
		total, vendorHi+vendorSuppressed, vendorSuppressed, pct, vendorHi, nonVendor)
	if vendorSuppressed == 0 {
		t.Error("vendor 过滤未产生任何压制效果，规则可能没生效")
	}
}

// 用报告里两条真实的高危误报，验证新的取值校验能把它们拦住。
func TestRealBatchHighSeverityFalsePositivesNowFiltered(t *testing.T) {
	doc := loadRealBatchReport(t)
	targets, _ := doc["targets"].([]any)

	var (
		sawPasswordFP bool
		sawKeyFP      bool
	)
	for _, ti := range targets {
		tm, ok := ti.(map[string]any)
		if !ok {
			continue
		}
		js, _ := tm["js"].(map[string]any)
		if js == nil {
			continue
		}
		fs, _ := js["findings"].([]any)
		for _, fi := range fs {
			fm, ok := fi.(map[string]any)
			if !ok || fm["severity"] != "high" {
				continue
			}
			ruleID, _ := fm["rule_id"].(string)
			value, _ := fm["value"].(string)
			context, _ := fm["context"].(string)
			switch ruleID {
			case "assign-password":
				// 真实误报：捕获到的是 `+ passWord +` 这种字符串拼接片段
				if strings.Contains(value, "+") {
					sawPasswordFP = true
					if !looksLikeCodeFragment(value) {
						t.Errorf("代码片段未被拦截: value=%q", value)
					} else {
						t.Logf("已拦截口令误报: value=%q", value)
					}
				}
			case "private-key":
				// 真实误报：库代码里拼接 PEM 文本，头后面没有 base64 主体
				idx := strings.Index(context, "PRIVATE KEY-----")
				if idx < 0 {
					continue
				}
				sawKeyFP = true
				end := idx + len("PRIVATE KEY-----")
				if hasPrivateKeyBody(context, end) {
					t.Errorf("无主体的 PEM 头未被拦截: context=%q", context)
				} else {
					t.Logf("已拦截私钥误报: context=%q", clip(context, 80))
				}
			}
		}
	}
	if !sawPasswordFP && !sawKeyFP {
		t.Skip("报告里没有这两类高危样本")
	}
	t.Logf("样本覆盖：口令拼接误报=%v，PEM 拼接误报=%v", sawPasswordFP, sawKeyFP)
}
