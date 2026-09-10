# 开发进度

> 每次开发完成（一个模块或一个开发会话结束）必须更新本文档。规则见 DESIGN.md 第 2.2 节。

## 总体进度

- [x] `httpx` — HTTP 客户端池：跟随重定向、跳过证书验证、限速、404 基线、代理
- [x] `target` — 目标解析：域名/IP:port → http+https 双协议探测
- [x] `config` — 配置文件加载与合并
- [x] `convert` — FingerprintHub nuclei YAML → 内部 JSON（服务 update 命令）
- [x] `fingerprint` — 指纹引擎：规则加载、四层兜底匹配（重定向/路径无关/子目录候选/手动 base-path）
- [x] `probe` — 漏洞点探测包：指纹→探测路径→内容匹配器 + 通用暴露面字典
- [x] `jsaudit` — JS 收集（深度1爬取+sourcemap）+ 七类规则提取 + base64 解码
- [x] `semantic` — LLM 语义层：OpenAI 兼容客户端，批量打分，可降级
- [x] `report` — JSON + HTML 报告
- [x] CLI 组装与联调

> **十个模块全部完成，v0.1.0 可用。** 全量测试 `go test -count=3 ./...` 通过；
> 本地无 gcc，`-race` 由 GitHub Actions CI 执行。

## 开发日志

### 2026-09-10 晚 — 实战复盘修复（113 目标批量扫描后）

处理了待办文档里 6 个"优先处理"项 + 复盘时新发现的 2 类高危误报。所有修复都有测试覆盖，
其中端点/注释/vendor 过滤与两类误报的修复都用**真实扫描报告的数据**做了量化验证
（`pkg/jsaudit/realdata_test.go`，报告缺失时自动跳过）。

**改动清单**

| 项 | 改动 | 实测效果 |
|---|---|---|
| 注释 URL 降噪 | 规则收紧为"只留同站/内网/公网 IP"，放弃域名黑名单 | 277 条 → 丢 268，降噪 **96.8%**，9 条有效信息全保留 |
| vendor 文件 | 文件名或 license 头识别，只跑高危规则 | 压制 **256/350** 条发现（73.1%），vendor 内 1 条高危保住 |
| 端点语法校验 | 定点黑名单（非白名单正则） | 907 → 剔除 61、保留 846，**124 条带 `:`/`*` 的 REST 路径全部保住** |
| API 文档端点 | 8 条移入通用字典，上限 20→30，从 `__always__` 移除 | 修掉 yhtipipc.com 那类 SPA 站点的漏报路径 |
| 接口前缀反哺 base | JS 审计提前到指纹/探测之前，前缀注入候选 base | 覆盖 nginx 反代前缀场景 |
| 暂停访问页 | `target.DetectSuspended` + 报告三端标注 | 案例 180.101.238.250:19094 不再被误读成"没问题" |
| 失败分类 | `httpx.ClassifyError` + `failure_reasons` 汇总 + `--retry` | 区分 62 超时 / 11 refused，只重试瞬时错误 |
| 高危误报 ×2 | `looksLikeCodeFragment`、`hasPrivateKeyBody` | 真实报告里两条高危误报均被拦截（有测试证明） |

**关键判断：两处推翻了待办文档里的原方案**（都以实测量化为依据）

1. 注释 URL 原方案是"维护公共域名黑名单"。实测 277 条里第三方域名 269 条**全是**噪声，
   有价值的是同站 1 条 + 内网 7 条——黑名单永远列不全，不如直接只留同站/内网。
   降噪率从黑名单方案的 66.8% 提升到 96.8%，且没少任何有效信息。
2. 端点校验原方案是白名单正则 `^/[a-zA-Z0-9_\-./?=&%]+$`。实测它会**误删 149 个合法端点**
   （Harbor 的 `/namespaces/:tenantNamespace/tenants/:tenantName/pods`、
   `/buckets/:bucketName/admin*`），而这些带路径参数/通配的接口恰恰是研判重点。
   改为定点黑名单后，脏数据照删、合法路径一个不少。

**失败率排查结论**：待办写的是"77 个 dial tcp 失败"，实际分类后是 **62 超时 + 11 refused
+ 1 TLS + 2 EOF + 1 DNS**。超时占八成，说明主因是**出口被丢包/防护设备限速**，
不是目标真死——所以没有盲目加"对所有失败重试"，而是只重试超时/连接切断这两类瞬时错误，
并在报告里给出"降低 --concurrency 或稍后重试"的提示。

### 2026-09-10 — CLI 组装与联调（最后一个模块）

**CLI**（`cmd/scanner`，14 个测试）
- `main.go`：flag 解析、`-u`/`-l` 目标汇总与去重、配置文件与命令行的优先级合并
  （用 `flag.Visit` 判断"显式设置过"才覆盖配置）、帮助与 `--version`
- `scan.go`：单目标编排——协议探测 → 指纹（四层兜底）→ 404 基线 → 暴露面探测 →
  JS 审计 →（语义层）→ 报告；目标级并发用带缓冲 channel 的 worker pool，
  单目标用 `context.WithTimeout` 限制总耗时
- `update.go`：`scanner update` **在内存中**下载并转换 GitHub zip（不落盘解包，
  避开 Windows 上的中文文件名与长路径问题），也支持 `--source-dir` 离线转换；
  产物被运行时优先加载，因此更新指纹库无需重编译
- 报告输出：终端彩色（自动判断终端/`NO_COLOR`）、JSON、自包含 HTML；
  `--json -` 支持输出到标准输出供管道消费
- README：完整用法 + **数据外发风险提示**（设计第 8 节要求）+ 行为边界说明

**联调中修掉的真实缺陷：**

1. **HTML 报告因非法 UTF-8 而整个文件无法解码**。根因有两处：
   ① `contextAround` / `Match` 按**字节**偏移切片，把一个多字节汉字切成半个；
   ② `clip` 在"无需截断"时直接返回原串，没有把非法字节规整掉。
   修复：切片按 UTF-8 字符边界对齐（`runeRange`），`clip` 统一返回 `string([]rune(s))`，
   并在 `Report.Finalize` 里对所有字符串做一次合法化（U+FFFD 替换）+ HTML 输出兜底。
   （目标站点大量使用 GBK，这个坑不修的话报告基本不可用。）
2. **颜色在管道/重定向时仍然输出 ANSI 转义**。改为默认按"标准输出是否为终端 + 是否设置
   `NO_COLOR`"决定，另加 `--no-color`/`--color` 强制开关。
3. `--rate` 原本被配置校验钳制成正数，导致无法表达"不限速"；改为 `0` 取默认、负数表示不限速。

**联调验证方式**（除单元测试外）：
- 用本地 HTTP 服务搭了一个演示目标（含 nacos 页面、内联/外部 JS、`.git/HEAD`、`.env`、
  JWT、Basic 头、内网 IP），跑真实二进制完整验证：七类发现全部命中，
  Basic 头解出 `admin:abcd@1234`，JWT payload 解出 `role:root`，接口路径正确提取且**未被请求**
- 用浏览器打开生成的 HTML 报告，DOM 检查确认：各区块齐全、17 个级别徽标、3 张表格、
  **无横向溢出**、`externalResources` 为空且仅 1 个内联样式表（自包含成立）

### 2026-09-10 — report 模块

**report**（`pkg/report`，21 个测试）
- 统一严重级别模型（critical/high/medium/low/info，中文展示），probe 与 jsaudit 的级别归一到此
- 三种输出：
  - 终端：严重=红底白字、高危=红、中危=黄；`Color=false`（NO_COLOR/重定向）时零 ANSI 转义；
    接口路径只列前 20 条，其余提示见报告文件
  - JSON：2 空格缩进 + 结尾换行，可回读（测试做了 round-trip）
  - HTML：**完全自包含**（内联 CSS、无任何外部资源），用 `html/template` 自动转义
- 汇总统计（目标成功/失败、各级别计数、请求数、耗时）与稳定排序（暴露面/JS 发现按严重度降序）
- 报告可携带语义层结论（每个 JS 发现一条 `semantic`），未启用时标记为未判定

**本模块修掉的真实缺陷：**

1. **JSON 输出无限递归导致栈溢出**：方法名用了 `MarshalJSON`，使 `*Report` 实现了
   `json.Marshaler`，而方法内部又调用 `json.MarshalIndent(r)` → 自我递归直到
   `fatal error: stack overflow`。改名为 `JSONBytes()`（注释里留了原因，避免以后又改回去）
2. 同时补了 httpx 的 POST 能力测试（`Body` 字段是我为 semantic 加的，回归确认 GET 不带请求体）

### 2026-09-10 — semantic 模块

**semantic**（`pkg/semantic`，13 个测试）
- OpenAI 兼容 `chat/completions`：`Authorization: Bearer`、temperature 0、非流式
- 复用 httpx 发请求（为此给 `httpx.Request` 加了 `Body []byte` 支持 POST），
  代理/超时/TLS 策略与扫描侧一致，语义层不限速
- "批量一次请求"落地为按批合并：单批 40 条、单次扫描最多外发 120 条，均可配
- 宽容解析模型输出：裸数组 / Markdown 代码块 / `{"results|items|data":[...]}` 三种形态
- **可降级**：无 api_key 时 `New` 返回 `ErrDisabled`（CLI 静默关闭）；单批失败不拖累其它批，
  HTTP 报错/垃圾输出都只记录错误，条目退回纯正则结论
- 置信度钳制 `[0,1]`，理由截断，未知/重复 item 忽略

### 2026-09-10 — jsaudit 模块（核心）

**jsaudit**（`pkg/jsaudit`，42 个测试）
- **收集**（`collect.go`）：外部 JS ≤30、内联脚本 ≤12、深度 1 同域页面 ≤8、单文件 ≤2MB 截断；
  `.js.map` 仅在含 `sourcesContent` 时收录（能还原源码）；内联脚本也分析
  （`application/json` 一并分析，模板类 `text/template` 跳过）
- **URL 归一化**：`//host/path` 首段像主机名→协议相对；不像主机名（如 `//static/js/x.js`）
  →按站内绝对路径处理；同时还原 `\/\/static\/js\/x.js` 这种 JS 转义写法
- **解码**（`decode.go`）：香农熵、base64 最多嵌套 2 层（还原 `admin:abcd@1234` 这类 `user:pass`）、
  JWT header/payload 解码、占位符/弱口令识别
- **七类规则**（`rules.go`）：硬编码凭证、云 AK/SK（AWS/阿里云/腾讯云/华为云）、Token、
  私钥、内网信息、接口路径、注释敏感信息；共 18 条正则
- **接口路径只提取不请求**（铁律），按 `(路径, 偏移)` 跨正则去重后计数，
  过滤静态资源与 `/static/`、`/node_modules/` 等噪声目录
- 语义层输入接口 `Report.Snippets()`：只外发需要复核的类别，**私钥与云 AK 不外发**
- 端到端测试专门断言"绝不请求 JS 中发现的接口"（记录服务端实际收到的路径，确认没有 `/api/*`）

**本模块修掉/发现的真实缺陷（均由测试暴露）：**

1. 内网 IP 正则把 `192.168` 分支与 `10` 分支共用同一段后缀，导致 `192.168.x.x` 需要 6 段才匹配
   —— **所有 192.168 段内网 IP 都被漏报**。已改为三段独立分支
2. `IsPlaceholder` 无条件生效，把 `AKIA…EXAMPLE`、`Bearer eyJ…abcdefg…` 这类**形态唯一**的
   真实命中当成占位符过滤掉。改为：形态唯一的规则（云 AK 前缀/私钥/JWT/Authorization 头）
   绕过占位符与熵值判断，只有"靠键名或熵值猜测"的规则才过滤
3. `fetch("/api/x")` 同时被路径正则与调用正则命中，接口出现次数被重复计数（4 次而非 2 次）。
   改为按 `(路径, 偏移)` 去重后计数
4. Go 正则的重复次数上限是 1000，`{16,2048}` 会在包初始化时 panic，已收敛到 `{16,1000}`
5. 注释类规则原本在全代码上匹配，代码字符串里出现"测试账号"字样会误报；改为只作用于注释文本，
   并排除 `http://` 这种伪注释

### 2026-09-10 — probe 模块

**probe**（`pkg/probe` + `rules/`）
- `rules/probe-packs.yaml`：26 个指纹族、7 条 `__always__`、90 条探测项；
  `rules/exposure.yaml`：通用暴露面字典正好 20 条（设计上限）
- 强制“每条路径必须带内容匹配器”：缺 matcher / matcher 空 / 正则不可编译一律在解析期报错，
  并列出全部问题（上限 20 条），不允许悄悄降级成“裸 200 即命中”
- matcher 默认大小写不敏感子串匹配，`regex: true` 时按 Go 正则；支持 `part: header` 匹配响应头
- 族触发：族名与指纹 `id`/`name`/`product`/`vendor`/`tags` 规范化后（小写、去 `-_. /`）子串比较，
  族名短于 3 字符不参与，避免噪声
- 新增特殊族键 `__always__`：不依赖指纹、对所有目标都跑，只放 Actuator / Swagger 这类
  高价值低开销路径（上游指纹库 99.9% 是根路径型，“是 Spring Boot 但没被识别”是常态，
  否则 springboot 的包永远跑不起来）
- 用 404 基线过滤软 404：`Baseline.SameAs()` 命中即跳过，裸 200 本身不算命中
- base 回退：探测项会在候选 base（`--base-path`、落地目录）下重试以应对子目录部署；
  每项最多 2 个 base；检测到通配 200 站点时主动减少 base 尝试并在 `Notes` 说明
- 开销上限：40 请求 / 族探测项 ≤24，且始终受 httpx 单目标总预算约束
- 两条针对真实文件的测试：① 规则文件可解析、字段合法、通用字典不超 20 条
  ② **每个族名都必须能被真实指纹库触发**（防止写出永远跑不起来的死包）——26 个族全部通过

### 2026-09-10 — httpx / target / config / convert / fingerprint 五个模块

按 DESIGN.md 第 2.2 节顺序实现，每个模块一次 commit 并 push。测试全部通过
（`go test -count=3 ./...` 全绿；本机无 gcc，`-race` 交由 CI）。

**httpx**（`pkg/httpx`）
- `Client`：跟随重定向并记录跳转链与最终 URL、默认跳过 TLS 证书校验、均匀间隔限速器（并发安全）、
  请求预算（默认 100/目标，`ErrBudgetExceeded`）、响应体读取上限与截断标记
- 代理：配置里的 `proxy` 优先，为空回退 `HTTPS_PROXY`/`HTTP_PROXY` 环境变量
- `Baseline`：随机路径取 404 基线，`SameAs()` 用「状态码 + 归一化 body 哈希」判定，
  通配 200（软 404）站点再用「同 Content-Type + 长度 3% 容差」兜底
- 响应同时保留原始字节（供 favicon 哈希）与文本

**target**（`pkg/target`）
- 解析 `域名` / `IP` / `IP:端口` / `域名:端口` / 完整 URL（路径作 base-path 提示）/ `#` 注释 / 空行，
  支持 IPv6 字面量与 `user:pass@host`，按 Key 去重并返回非法行列表
- 协议策略：https 优先 http 兜底；`--both` 时两个协议各自探活
- `Probe` 返回 `Site`（落地页、最终路径、候选 base）；base-path 404 时自动补取站点根
- 发现并处理：TLS-only 端口收到明文请求会返回 400（各服务端有固定文案），
  按“该协议未提供服务”处理，避免把 https 站点误报成 http 可用

**config**（`pkg/config`）
- 查找顺序：`--config` > 当前目录 `config.yaml` > 可执行文件同目录 `config.yaml`；缺失即用默认值
- 自定义 `Duration` 支持 `30s` 与裸数字（按秒）；`KnownFields(true)` 让拼错的字段名直接报错
- 默认值填充 + 取值范围钳制；`SemanticEnabled()`（无 api_key 自动关闭语义层）、`MaskedAPIKey()` 脱敏
- 新增 `config.yaml.example`（内容与 `config.Example()` 同源）

**convert**（`pkg/convert`）
- 从 `fs.FS` 读取（磁盘目录或 zip 均可，为 `scanner update` 直接从压缩包转换铺路）
- 只保留 path + word/regex/favicon；含 `dsl`/`status`/`size`/`extractors` 的 matcher 丢弃并计入 `Stats`
- 重复 ID 加 `#N` 后缀**全部保留**（上游 73 个 ID 被复用），按 ID 排序保证产物可复现
- 实测上游 3371 个模板 → **3373 条规则、0 解析失败、0 matcher 丢弃**，产物 `fingerprints.json` 约 960KB
- 交叉核对：word 3032 / regex 475 / favicon 281，与上游原始计数完全一致
  （唯一差值的 1 个 `type: regex` 位于 `extractors` 里，不是 matcher）

**fingerprint**（`pkg/fingerprint`）
- `Library`/`Rule`/`Matcher` 数据模型 + `Load`（磁盘 `fingerprints.json` 优先，缺失回退 go:embed，
  因此 `scanner update` 后无需重编译）
- mmh3（MurmurHash3 x86_32）纯 Go 实现，参考值由 Python `mmh3` 库交叉验证
  （`hello`→613153351、`foo`→-156908512 等 7 组向量 + md5 向量）
- favicon 匹配同时支持 md5 与 mmh3（有符号十进制 / 有符号十六进制 / 无符号十六进制）
- `NewEngine` 预编译全部正则并建索引（根路径规则、favicon 规则、路径→规则），
  无效正则的规则整条剔除并计入 `RegexSkipped`
- `Scan` 实现四层兜底：① 根路径重定向后的落地页 ② 路径无关 body/header 关键字与 favicon
  （`<link rel="icon">` 真实位置，失败回退 `/favicon.ico`）③ 候选子目录 base × 规则路径
  ④ `--base-path` 手动指定；按规则 ID 去重并按产品名排序
- 真实指纹库集成测试 6 项：规模与 matcher 组成、索引正确性、nacos 端到端、
  子目录 base 兜底、非根路径规则（etcd `/version`）、`and` 条件不部分命中

### 2026-09-10 — 环境更新与 CI 接入

- Go 已重装为 `go1.27.1 windows/amd64`（`C:\Program Files\Go`），原 32 位卸载，全局 env 无残留配置
- 本机仍无 gcc：新增 GitHub Actions CI（`.github/workflows/ci.yml`），push/PR 到 main 自动在 windows-latest 跑 `go vet` + `go test -race` + `go build`；本地继续 `-count=3` 方案
- DESIGN.md 新增第 2.4 节"开发环境与测试"，merge 前 CI 必须全绿
- 待办不变：按 DESIGN.md 第 2.2 节顺序从 `httpx` 开始实现

### 2026-09-10 — 项目重置，重新开发

- 应使用者要求清除上一轮全部开发成果：代码（`pkg/`、`go.mod`、`go.sum`）、git 历史、远程 tag 已全部清空
- 保留：DESIGN.md（设计定稿，仍是开发唯一依据）、README.md、.gitignore、本文档
- 当前进度：零代码，从第一个模块重新开始
- 待办：按 DESIGN.md 第 2.2 节顺序开工，第一步实现 `httpx`

## 遇到的问题及解决方式

1. **DESIGN.md 写的 favicon 是 mmh3，上游实际用 md5**
   实测 FingerprintHub 的 281 条 favicon matcher 里绝大多数是 32 位十六进制 md5，
   仅个别规则（如 xxl-job）用 mmh3 十进制。解决：两种都支持，按哈希串形态自动判别。
   已回写 DESIGN.md 第 5.2 节。（mmh3 实现用 Python `mmh3` 库做了 7 组参考向量验证。）

2. **上游 73 个规则 ID 被多个模板复用**
   最初按 ID 去重会丢掉约 51 条规则。改为加 `#N` 后缀全部保留，产物 3373 条与模板数吻合。

3. **TLS-only 端口对明文请求返回 400，被误判为 http 可用**
   加了针对性的 400 文案识别（Go/nginx 的固定提示），按协议不可用处理。

4. **`MatchRootRules bool` 零值语义反了**（默认 false 导致根规则全不匹配）
   改为反向字段 `SkipRootMatch`，零值即“要匹配”。

5. **规则 `paths: ["/", "/nacos/"]` 时 `/` 未被匹配**
   原来只有“纯根路径”规则才进 rootIdx，导致含 `/` 的多路径规则白丢一次免费匹配。
   改为：paths 中出现 `/` 即加入 rootIdx，其余非根路径另行探测。

6. **父级路径为 `.cache/` 时 go 工具忽略该目录**
   临时转换工具改用 `tools/genfp`（用完即删），`.cache/` 只放 FingerprintHub 源码克隆（已 gitignore）。

## 下次开发待办

### 实战扫描暴露的问题（2026-09-10 晚，113 目标批量扫描后）— **已全部处理**

基于 `.cache/reports/scan-20260910-231347.json` 的分析结论与修复结果：

- [x] **jsaudit 降噪（最高优先）**：350 条 finding 中 332 条是 `comment-url` 噪音。
  **实测修正了原方案的判断**：对 277 条去重注释 URL 分类后发现，第三方域名 269 条
  **全部**是库文档/规范/教程噪声，有价值的只有同站 1 条 + 内网 7 条。因此放弃了
  "维护公共域名黑名单"（永远列不全），改为高精度规则：**注释 URL 只保留同站/内网/公网 IP**，
  降噪率 **96.8%**（268/277 丢弃）且 9 条有效信息一条没少。
  另加 vendor 规则（文件名或 license 头识别）：vendor 文件只跑高危规则，
  实测压制 **256/350 = 73.1%** 的发现，同时保留了 vendor 内的 1 条高危
- [x] **jsaudit 端点提取加语法校验**：**原方案的 `^/[a-zA-Z0-9_\-./?=&%]+$` 会误删
  149 个合法端点**（Harbor 的 `/namespaces/:tenantNamespace/tenants/:tenantName/pods`、
  `/buckets/:bucketName/admin*` 等带 REST 参数的路径），改为**定点黑名单**：
  907 个去重端点剔除 61 个脏数据，保留 846 个（其中 124 个带 `:`/`*` 参数全部保住）
- [x] **API 文档端点提升为通用探测**：`/v2/api-docs`、`/api/v2/api-docs`、`/v3/api-docs`、
  `/api/v3/api-docs`、`/swagger-ui.html`、`/openapi.json` 等 8 条移入通用暴露面字典，
  并从 `__always__` 族移除以免重复请求；字典上限由 20 放宽到 30（`MaxGenericEntries`）
- [x] **JS 接口前缀反哺候选 base**：新增 `Report.BasePrefixCandidates`（出现 ≥3 次、
  排除停用表、按次数取前 3），并把 pipeline 调整为 **JS 审计先于指纹/探测**，
  使前缀能喂给两层候选 base；前缀全部来自目标自身 JS，不违反"不做目录爆破"
- [x] **暂停访问页识别**：`target.DetectSuspended` 按 URL 特征（`offtime`/`maintenance`）
  与页面文案（`系统暂停访问`、`网站维护中`、`under maintenance` 等，只看标题与正文前 8KB）判定；
  报告中 JSON 带 `suspended` 字段、终端打印警告行、HTML 显示徽标
- [x] **失败率排查**：实测 **62 个是超时、11 个 connection refused**（而非笼统的 77 个
  `dial tcp`）。超时占八成说明主因是出口被丢包/限速而非目标真死，因此：
  新增 `httpx.ClassifyError` 把失败分为 timeout/refused/dns/tls/eof/protocol/other，
  报告新增 `failure_reasons` 分布并在超时占多数时给出可操作提示；
  新增 `--retry <n>` **只对可重试的瞬时错误**（超时/连接被切断）重试并指数退避，
  对 refused/DNS 不重试

### 本轮额外发现并修掉的两类高危误报

复盘真实报告时发现两条**高危**误报（危害大于低危噪声），已加针对性校验并用真实数据验证：

- [x] `assign-password` 捕获到 `+ passWord +`：源头是
  `"&password=" + passWord + "&IsRememberUser=" + ...` 这类 URL 拼接代码。
  新增 `looksLikeCodeFragment`，取值含字符串拼接特征即丢弃
- [x] `private-key` 命中 jsencrypt 的 `getPrivateKey()`：该函数把 PEM 头写成字面量、
  后面紧跟 `wordwrap` 拼接代码，并非真实私钥——**任何使用 JS 加密库的站点都会误报高危**。
  新增 `hasPrivateKeyBody`：PEM 头与 END 之间必须有 ≥100 个 base64 字符才判定

### 已验证完成（原待办项）

十个模块全部实现，以下均已落地并有测试覆盖：

- [x] `probe` 指纹族探测包 + 通用暴露面字典（20 条）+ 内容匹配器强制校验 + 基线过滤软 404
- [x] 根 `embed.go` 嵌入 `fingerprints.json` 与 `rules/*.yaml`
- [x] `jsaudit` JS 收集（深度 1 + `.js.map`）、七类规则、base64 最多嵌套 2 层
- [x] `semantic` / `report` / CLI 组装（含 `scanner update`：拉取 zip 在内存中转换，不落盘解包）
- [x] README 明示数据外发风险（设计第 8 节要求）

### CI 验证

每次 commit 推送后 `.github/workflows/ci.yml` 均通过（`windows-latest` 上
`go vet` + `go test -race -count=1` + `go build`）。最近 6 个 commit 全绿，
包括最新一次 CLI 组装：

```
712bd0b  completed  success   cli: CLI 组装 …
492f8f7  completed  success   report: 统一严重级别模型 …
f64a922  completed  success   semantic: OpenAI 兼容语义层 …
071cc28  completed  success   jsaudit: JS 收集 …
bbfe1c5  completed  success   probe: 指纹族探测包 …
ef9ea30  completed  success   convert+fingerprint: FingerprintHub 模板转 JSON …
```

本机无 gcc，`-race` 只在 CI 执行，因此**改代码后必须确认 CI 绿**再认为完成。

### 建议的后续增强（非阻塞）

- [ ] `probe-packs.yaml` 的 matcher 目前是按产品文档整理的**最佳猜测**，建议对真实目标
      逐个校准（尤其是 `harbor`/`jumpserver`/`minio` 等接口路径与返回特征）
- [ ] 指纹库的 favicon 规则里 mmh3 与 md5 混用，若上游后续统一格式，`FaviconMatches`
      可收敛为单一格式
- [ ] `semantic` 目前串行为每个目标单独调用；目标很多时可考虑跨目标合并批次以省调用次数
- [ ] JS 收集的深度 1 爬取只取同域链接，若目标把 JS 放在同域 CDN 之外会漏；可按需加白名单
- [ ] HTML 报告可加"仅显示高危"的筛选开关（纯前端，无外部依赖）
- [ ] 可考虑 `--resume`/结果缓存，避免重复扫描同一目标

