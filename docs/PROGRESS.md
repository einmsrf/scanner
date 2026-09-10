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
- [ ] `semantic` — LLM 语义层：OpenAI 兼容客户端，批量打分，可降级
- [ ] `report` — JSON + HTML 报告
- [ ] CLI 组装与联调

## 开发日志

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

- [ ] `probe`：`rules/probe-packs.yaml` 按指纹族组织探测路径（每条必须带内容匹配器），
      通用暴露面字典 ≤20 条，用 httpx 的 `Baseline` 过滤软 404 误报
- [ ] `rules/` 目录建好后，在根 `embed.go` 里补 `//go:embed rules/*.yaml`
- [ ] `jsaudit`：JS 收集（深度 1 + `.js.map`）、七类规则、base64 最多嵌套 2 层解码、熵值 >4.0 才判疑似密钥
- [ ] 后续 `semantic` / `report` / CLI 组装（含 `scanner update`：从 GitHub 拉取 zip 直接转换，不落盘解包）
