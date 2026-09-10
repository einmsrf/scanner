package jsaudit

import (
	"regexp"
	"strings"
)

// Category 是七类检测规则之一（DESIGN.md 第 7.2 节）。
type Category string

// 七类规则。
const (
	CatCredential Category = "hardcoded-credential" // 硬编码凭证
	CatCloudKey   Category = "cloud-aksk"           // 云 AK/SK
	CatToken      Category = "token"                // Token
	CatPrivateKey Category = "private-key"          // 私钥
	CatInternal   Category = "internal-info"        // 内网信息
	CatEndpoint   Category = "endpoint"             // 接口路径
	CatComment    Category = "comment-secret"       // 注释敏感信息
)

// Display 返回中文类别名。
func (c Category) Display() string {
	switch c {
	case CatCredential:
		return "硬编码凭证"
	case CatCloudKey:
		return "云 AK/SK"
	case CatToken:
		return "Token"
	case CatPrivateKey:
		return "私钥"
	case CatInternal:
		return "内网信息"
	case CatEndpoint:
		return "接口路径"
	case CatComment:
		return "注释敏感信息"
	default:
		return string(c)
	}
}

// Severity 是级别。
type Severity string

// 级别取值（与 probe 层保持一致）。
const (
	SevHigh   Severity = "high"
	SevMedium Severity = "medium"
	SevLow    Severity = "low"
	SevInfo   Severity = "info"
)

// Display 返回中文级别名。
func (s Severity) Display() string {
	switch s {
	case SevHigh:
		return "高危"
	case SevMedium:
		return "中危"
	case SevLow:
		return "低危"
	case SevInfo:
		return "信息"
	default:
		return string(s)
	}
}

// minEntropyByRule 覆盖个别规则的熵值门槛。
//
// DESIGN.md 第 7.2 节要求“熵值 >4.0 才进入疑似密钥判断”。该门槛用于
// **纯粹靠形态猜测**的场景（如 generic-access-key-id）。而 `password: "xxx"`
// 这类带明确键名的赋值本身已是高信号，且真实短口令的熵天然低于 4.0
// （例如设计文档里的 admin:abcd@1234，密码段熵约 3.2），故用更低门槛 +
// 占位符黑名单来控误报。private-key / jwt / 云厂商 AK 前缀 / Authorization
// 等形态唯一的规则直接绕过熵值判断。
var minEntropyByRule = map[string]float64{
	"generic-access-key-id":    EntropyThreshold,
	"assign-password":          2.5,
	"assign-secret":            3.0,
	"assign-token":             3.0,
	"aliyun-access-key-secret": 3.0,
	"tencent-secret-key":       3.0,
	"huawei-access-key":        3.0,
}

// minEntropy 返回该规则要求的敏感值最小熵。
func (r rule) minEntropy() float64 {
	if v, ok := minEntropyByRule[r.ID]; ok {
		return v
	}
	if r.HighConfidence {
		return 0
	}
	return EntropyThreshold
}

// 一条规则的匹配方式。HighConfidence 为真表示“形态本身即高置信”，
// 不受熵值门槛限制（例如 Authorization 头、已知的 AK 前缀、私钥头）。
type rule struct {
	ID             string
	Category       Category
	Severity       Severity
	Re             *regexp.Regexp
	ValueGroup     int  // 取哪个捕获组作为敏感值；0 表示用整个匹配
	HighConfidence bool // 是否绕过熵值门槛
	MinLen         int  // 敏感值最小长度
	DecodeBase64   bool // 是否对敏感值做嵌套 base64 解码
	DecodeJWT      bool // 是否按 JWT 解析 header/payload
	Hint           string
}

// 占位符/示例值过滤 + 熵值门槛都通过的才算“疑似真实密钥”。
var rules = []rule{
	// ---------- 硬编码凭证 ----------
	{
		ID: "auth-basic", Category: CatCredential, Severity: SevHigh,
		Re:             regexp.MustCompile(`(?i)authorization["'\s:=]{1,4}basic\s+([A-Za-z0-9+/=_-]{8,512})`),
		ValueGroup:     1,
		HighConfidence: true,
		DecodeBase64:   true,
		MinLen:         8,
		Hint:           "Authorization: Basic 头，base64 已还原",
	},
	{
		ID: "auth-bearer", Category: CatCredential, Severity: SevHigh,
		Re:         regexp.MustCompile(`(?i)authorization["'\s:=]{1,4}bearer\s+([A-Za-z0-9\-._~+/=]{16,1000})`),
		ValueGroup: 1, HighConfidence: true, MinLen: 16,
		Hint: "Authorization: Bearer 头",
	},
	{
		ID: "assign-password", Category: CatCredential, Severity: SevHigh,
		Re:         regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|pass)\s*[:=]\s*["']([^"'\r\n]{4,128})["']`),
		ValueGroup: 1, MinLen: 4,
		Hint: "密码赋值",
	},
	{
		ID: "assign-secret", Category: CatCredential, Severity: SevHigh,
		Re:         regexp.MustCompile(`(?i)\b(?:client[_-]?secret|app[_-]?secret|appsecret|secret[_-]?key|secretkey|private[_-]?key)\s*[:=]\s*["']([^"'\r\n]{6,256})["']`),
		ValueGroup: 1, MinLen: 6,
		Hint: "密钥赋值",
	},

	// ---------- 云 AK/SK ----------
	{
		ID: "aws-access-key-id", Category: CatCloudKey, Severity: SevHigh,
		Re:         regexp.MustCompile(`\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16})\b`),
		ValueGroup: 1, HighConfidence: true, MinLen: 20,
		Hint: "AWS AccessKeyId",
	},
	{
		ID: "aws-secret-key", Category: CatCloudKey, Severity: SevHigh,
		Re:         regexp.MustCompile(`(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']`),
		ValueGroup: 1, HighConfidence: true, MinLen: 40,
		Hint: "AWS SecretAccessKey",
	},
	{
		ID: "aliyun-access-key-id", Category: CatCloudKey, Severity: SevHigh,
		Re:         regexp.MustCompile(`\b(LTAI[0-9A-Za-z]{12,24})\b`),
		ValueGroup: 1, HighConfidence: true, MinLen: 16,
		Hint: "阿里云 AccessKeyId",
	},
	{
		ID: "aliyun-access-key-secret", Category: CatCloudKey, Severity: SevHigh,
		Re:         regexp.MustCompile(`(?i)access[_-]?key[_-]?secret\s*[:=]\s*["']([A-Za-z0-9]{20,64})["']`),
		ValueGroup: 1, MinLen: 20,
		Hint: "阿里云 AccessKeySecret",
	},
	{
		ID: "tencent-secret-id", Category: CatCloudKey, Severity: SevHigh,
		Re:         regexp.MustCompile(`\b(AKID[0-9A-Za-z]{13,32})\b`),
		ValueGroup: 1, HighConfidence: true, MinLen: 17,
		Hint: "腾讯云 SecretId",
	},
	{
		ID: "tencent-secret-key", Category: CatCloudKey, Severity: SevHigh,
		Re:         regexp.MustCompile(`(?i)(?:tencent|qcloud)[_-]?secret[_-]?key\s*[:=]\s*["']([A-Za-z0-9]{24,64})["']`),
		ValueGroup: 1, MinLen: 24,
		Hint: "腾讯云 SecretKey",
	},
	{
		ID: "huawei-access-key", Category: CatCloudKey, Severity: SevHigh,
		Re:         regexp.MustCompile(`(?i)(?:huawei|hw)[_-]?(?:access[_-]?key|ak)\s*[:=]\s*["']([A-Z0-9]{16,32})["']`),
		ValueGroup: 1, MinLen: 16,
		Hint: "华为云 AccessKey",
	},
	{
		ID: "generic-access-key-id", Category: CatCloudKey, Severity: SevMedium,
		Re:         regexp.MustCompile(`(?i)(?:access[_-]?key[_-]?id|accesskeyid|access[_-]?id)\s*[:=]\s*["']([A-Za-z0-9]{16,64})["']`),
		ValueGroup: 1, MinLen: 16,
		Hint: "通用 AccessKeyId 赋值",
	},

	// ---------- Token ----------
	{
		ID: "jwt", Category: CatToken, Severity: SevMedium,
		Re:         regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,})`),
		ValueGroup: 1, HighConfidence: true, MinLen: 30,
		DecodeJWT: true,
		Hint:      "JWT，header/payload 已解码",
	},
	{
		ID: "assign-token", Category: CatToken, Severity: SevMedium,
		Re:         regexp.MustCompile(`(?i)\b(?:api[_-]?key|apikey|access[_-]?token|accesstoken|auth[_-]?token|authtoken|app[_-]?key|appkey)\s*[:=]\s*["']([A-Za-z0-9\-._~+/=]{12,512})["']`),
		ValueGroup: 1, MinLen: 12,
		Hint: "apiKey/token 赋值",
	},

	// ---------- 私钥 ----------
	{
		ID: "private-key", Category: CatPrivateKey, Severity: SevHigh,
		Re:         regexp.MustCompile(`(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |ENCRYPTED RSA )?PRIVATE KEY-----)`),
		ValueGroup: 1, HighConfidence: true, MinLen: 10,
		Hint: "私钥文件内容",
	},

	// ---------- 内网信息 ----------
	{
		ID: "internal-ip", Category: CatInternal, Severity: SevLow,
		Re:         regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b`),
		ValueGroup: 1, HighConfidence: true, MinLen: 7,
		Hint: "内网 IP",
	},
	{
		ID: "internal-domain", Category: CatInternal, Severity: SevLow,
		Re:         regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9-]{0,62}\.(?:internal|corp|intranet|lan|local))\b`),
		ValueGroup: 1, HighConfidence: true, MinLen: 8,
		Hint: "内网/内部域名",
	},

	// ---------- 注释敏感信息 ----------
	{
		ID: "comment-test-account", Category: CatComment, Severity: SevLow,
		Re:         regexp.MustCompile(`(?i)(?:测试账号|测试用户|测试密码|默认账号|默认密码|test[ _-]?account|default[ _-]?password|demo[ _-]?account)\s*[:：=]?\s*([^\s,;'"<>]{2,64})?`),
		ValueGroup: 1, HighConfidence: true, MinLen: 2,
		Hint: "注释中的测试/默认账号信息",
	},
}

// Compiled 便于测试与自检。
type compiledRule struct {
	spec rule
	re   *regexp.Regexp
}

var compiledRules = func() []compiledRule {
	out := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, compiledRule{spec: r, re: r.Re})
	}
	return out
}()

// AllRules 返回规则 ID 列表（供自检/文档）。
func AllRules() []string {
	out := make([]string, 0, len(compiledRules))
	for _, c := range compiledRules {
		out = append(out, c.spec.ID)
	}
	return out
}

// endpointRe 提取接口路径与绝对 URL。
var (
	absURLRe   = regexp.MustCompile("[\"'`]((?:https?:)?//[^\"'`\\s]{4,300})[\"'`]")
	relPathRe  = regexp.MustCompile(`["'\x60](/[A-Za-z0-9_\-./{}$:@!~*+]{2,200}(?:\?[^"'\x60\s]{0,200})?)["'\x60]`)
	callPathRe = regexp.MustCompile(`(?i)(?:fetch|axios(?:\.\w+)?|\.open|\.ajax|url)\s*\(\s*["'\x60]([^"'\x60\s]{3,300})["'\x60]`)
)

// staticExts 是明显不是接口的静态资源后缀。
var staticExts = map[string]bool{
	".js": true, ".css": true, ".map": true, ".png": true, ".jpg": true,
	".jpeg": true, ".gif": true, ".svg": true, ".ico": true, ".webp": true,
	".bmp": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".otf": true, ".mp4": true, ".mp3": true, ".webm": true, ".pdf": true,
	".zip": true, ".gz": true, ".txt": true, ".html": true, ".htm": true,
	".json": true, ".xml": true, ".csv": true, ".xls": true, ".xlsx": true,
	".doc": true, ".docx": true, ".ppt": true, ".pptx": true,
}

// noisePathFragments 是明显与业务接口无关的路径片段。
var noisePathFragments = []string{
	"/static/", "/assets/", "/node_modules/", "/webpack", "/dist/", "/build/",
	"/images/", "/img/", "/fonts/", "/css/", "/js/", "/media/", "/favicon",
	"/.well-known/", "/sourcemap", "/@vite/", "/@react-refresh",
}

// blockCommentRe / lineCommentRe 用于提取 JS 注释。
var (
	blockCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineCommentRe  = regexp.MustCompile(`(?m)(?:^|[^:"'\\])//([^\n]{2,600})`)
)

// commentURLRe 匹配注释里的文档/内网地址。
var commentURLRe = regexp.MustCompile(`((?:https?|ftp)://[^\s"'<>]{4,300})`)

// isStaticURL 判断 URL/路径是否指向静态资源（不当作接口）。
func isStaticURL(p string) bool {
	low := strings.ToLower(p)
	if i := strings.IndexAny(low, "?#"); i >= 0 {
		low = low[:i]
	}
	for ext := range staticExts {
		if strings.HasSuffix(low, ext) {
			return true
		}
	}
	return false
}

// isNoisePath 判断路径是否属于静态资源目录等噪声。
func isNoisePath(p string) bool {
	low := strings.ToLower(p)
	for _, frag := range noisePathFragments {
		if strings.Contains(low, frag) {
			return true
		}
	}
	return false
}
