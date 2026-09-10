# Scanner 设计文档（定稿）

> 本文档是开发的唯一依据。开发前通读全文；任何设计变更先改本文档再改代码。

## 1. 定位

Go 编写的单文件 CLI 工具：输入域名/IP(:port)，自动补全 http/https，识别 Web 指纹，按指纹探测已知暴露面，审计 JS 中的敏感信息与接口（**只分析、绝不主动请求 JS 中发现的接口**），正则初筛 + LLM 语义打分降低误报。

核心逻辑全部在 `pkg/` 下，CLI 是薄壳，未来加 GUI 只需包一层。

## 2. 开发流程约定（必须遵守）

### 2.0 铁律：操作范围限制（最不能违反的规则）

**一切操作必须在本项目文件夹（`scanner/`）内进行，不得读写、创建、修改、删除其他任何文件夹及文件。** 包括但不限于：

- 代码、文档、测试数据、临时文件一律放在项目目录内
- 不读写用户主目录（`~`）、系统目录、其他项目目录
- 配置文件、日志、扫描结果输出的默认路径都在项目目录内
- 安装依赖只允许写入项目目录（Go module 缓存除外，那是 Go 工具链自身行为）
- 任何需要越出项目目录的操作，必须先停下来向使用者确认

### 2.1 Git 版本管理

- 所有开发在 git 仓库中进行（本仓库已初始化，主分支 `main`）。
- **每完成一个模块就 commit 一次**，commit message 格式：`<模块>: <做了什么>`，例如 `httpx: 实现 404 基线探测与限速`。
- **每次 commit 后必须立即 `git push` 推送到 GitHub（origin/main），不允许只提交到本地**；tag 随 commit 一起推送（`git push --follow-tags`）。开发会话结束前必须确认 `git status` 无 ahead 提示，有未推送内容视为本次开发未完成。
- 里程碑打 tag：`v0.1-httpx`、`v0.2-fingerprint` …… 正式可用版本 `v1.0`。
- 需要回滚时：单次改动用 `git revert <commit>`；整体回到某个里程碑用 `git reset --hard <tag>`（回滚前先 `git tag backup-<date>` 打备份点）。
- 新功能尝试开分支 `feature/<name>`，验证通过后合并回 `main`。

### 2.2 开发进度文档

- **每次开发完成（一个模块或一个开发会话结束）必须更新 `docs/PROGRESS.md`**，内容包括：
  - 本次完成的内容（对应 commit hash）
  - 当前整体进度（模块清单打勾）
  - 遇到的问题及解决方式
  - 下次开发的待办事项
- 开发顺序：`httpx → target → fingerprint/convert → probe → jsaudit → semantic → report → CLI 组装`。

### 2.3 网络代理

- GitHub 访问不通时（如 `scanner update` 拉取 FingerprintHub 失败、go mod 下载失败），**使用本机代理 `http://127.0.0.1:7890`**，不要因网络问题停滞（注意遵守 2.0 铁律，以下配置都只写项目内或仅当前会话生效，**禁止用 `--global` 或 `go env -w` 写全局配置**）：
  - git（仅本仓库生效）：`git config http.proxy http://127.0.0.1:7890`
  - Go（仅当前会话环境变量）：`export GOPROXY=https://goproxy.cn,direct`（国内镜像优先），必要时 `export HTTPS_PROXY=http://127.0.0.1:7890`
  - 程序本身的 HTTP 客户端：支持 `HTTPS_PROXY` 环境变量和配置文件中的 `proxy` 字段

### 2.4 开发环境与测试

- **本机 Go**：`go1.27.1 windows/amd64`，位于 `C:\Program Files\Go`（2026-09-10 重装为 64 位，原 32 位已卸载）。注意：旧的 shell 会话 PATH 可能未刷新，找不到 `go` 时用绝对路径 `C:\Program Files\Go\bin\go.exe`
- **竞态检测**：本机无 gcc，`go test -race` 无法在本地运行。统一由 GitHub Actions CI 执行（`.github/workflows/ci.yml`，windows-latest 自带 mingw-w64 gcc）：每次 push/PR 到 main 自动跑 `go vet`、`go test -race -count=1 ./...`、`go build ./...`
- **本地测试**：`go test -count=3 ./...` 重复跑 + 人工复核共享状态，是 CI 竞态检测的补充而非替代；**merge 前 CI 必须全绿**
- 发布构建：`GOARCH=amd64 CGO_ENABLED=0 go build` 产出单文件

## 3. 输入与目标处理

- 单目标：`scanner -u example.com`；批量：`scanner -l targets.txt`
- targets.txt 支持：`域名` / `IP` / `IP:端口` / `域名:端口` / 完整 URL（路径部分作为 base-path 提示）/ `#` 注释行 / 空行
- 协议策略：默认 https 优先、失败降级 http；`--both` 双协议都扫
- 跟随重定向，对**最终落地页**做指纹匹配
- 默认跳过 TLS 证书验证（大量目标是自签证书或 IP 直连）

## 4. 配置文件

- 查找顺序：`--config` 指定 > 项目根目录 `config.yaml`（**遵守 2.0 铁律，不读取项目外的任何路径**）
- 配置文件示例：

```yaml
llm:
  base_url: "https://api.deepseek.com/v1"   # OpenAI 兼容接口，DeepSeek/通义/Kimi 均可
  api_key: "sk-xxx"
  model: "deepseek-chat"
  timeout: 30s

proxy: "http://127.0.0.1:7890"   # 可选，访问外网/GitHub 不通时启用

scan:
  concurrency: 10      # 目标级并发
  qps: 5               # 单目标 QPS
  timeout: 10s         # 单请求超时
```

- 命令行参数优先级高于配置文件；`llm.api_key` 为空时语义层自动降级关闭

## 5. 指纹识别

### 5.1 指纹库

- 复用 [FingerprintHub](https://github.com/0x727/FingerprintHub)
- 写离线转换器（`pkg/convert`）：nuclei YAML 模板子集 → 紧凑 JSON，`go:embed` 进二进制。DSL 表达式等复杂规则直接丢弃
- `scanner update` 命令：从 GitHub 拉取 FingerprintHub 最新版本重新转换（网络不通时走配置文件的 proxy）

**上游实际情况（2026-09-10 核对，commit `eb8bcacd`，实测数据，实现以实际为准）：**

- 模板位于仓库的 `web-fingerprint/` 目录，共 3371 个 YAML 文件；转换后 3373 条规则（有 2 个模板含多个 `http` 块）
- matcher 类型只有三种：`word`（3032）、`regex`（476，其中 1 个属于 `extractors` 不算 matcher）、`favicon`（281）。**上游不存在 `status` matcher，也没有 DSL**，所以“丢弃复杂规则”实际只作用于个别含 `extractors` 的模板
- 73 个 ID 被多个模板复用（同产品不同入口），转换时**全部保留并加 `#N` 后缀**去重，避免丢失探测能力
- 每条模板的 `condition: and` 是**单个 matcher 内部**多项之间的关系（默认 `or`）；上游不出现 `matchers-condition`，故 matcher 之间按 nuclei 默认的 `or` 处理
- 上游正则可 100% 编译，无丢弃

### 5.2 匹配策略（四层兜底，应对部署目录被修改）

1. **重定向跟随**：根路径 302 到真实入口（`/ → /oa/login.do`），对落地页匹配
2. **路径无关规则**：body 关键字、header、favicon 哈希（favicon 同时解析 `<link rel="icon">` 拿真实位置，不只用 `/favicon.ico`）
3. **子目录候选**：从落地页 HTML/JS 提取站内一级目录，按出现频率取 Top 5，把路径型规则的 base 从 `/` 换成候选目录重新拼接
4. **手动指定**：`--base-path` 参数

- 不做目录爆破（不内置 `/oa` `/system` 等猜测字典）
- 单目标请求预算硬上限 ~100 个

**实现要点（实测后补充，见 5.1 的核对结论）：**

- **favicon 哈希同时支持两种写法**：上游 281 条 favicon matcher 里绝大多数是 **md5**（32 位十六进制），个别是 **mmh3**（如 xxl-job 用十进制 `1691956220`）。匹配时按哈希串形态自动判别，并兼容 mmh3 的有符号十进制、有符号十六进制、无符号十六进制三种写法
- **第 3 层主要作用于根路径型规则**：上游 3370/3373 条规则路径都是 `{{BaseURL}}/`，所以“换 base 重拼”实际是拿候选子目录（如 `/app`）去请求 `origin/app/`，再用**根路径型规则**匹配该页面。这是“部署目录被修改”（应用挂在 `/app` 而根路径只是个门户页）场景下的主要兜底手段
- 含 `{{RootURL}}`、`{{Hostname}}` 等无法静态化变量的 path 一律丢弃（上游几乎不用）
- 引擎自身开销上限：子目录候选 ≤5、候选 base 探测 ≤8、非根路径探测 ≤60，且受 httpx 的单目标总预算约束

## 6. 漏洞点探测（仅判活，不发任何 payload）

- `rules/probe-packs.yaml`：按指纹族组织探测路径，**每条路径必须带内容匹配器**（返回体含特征串才算命中，不看裸 200）。示例：

```yaml
springboot:
  - path: /actuator/env
    matcher: "propertySources"
  - path: /swagger-ui.html
    matcher: "swagger"
  - path: /v2/api-docs
    matcher: "\"paths\""
```

- 通用暴露面字典 ≤20 条（`.git/HEAD`、`/.env`、`/robots.txt`、常见备份文件），对所有目标都跑
- **404 基线**：每个目标先请求一个随机路径记录返回特征，通配 404 返回 200 的站点用基线比对防误报

**实现要点（实测后补充）：**

- 探测项字段：`path`、`matcher` 必填；可选 `name`（报告展示名）、`severity`（critical/high/medium/low/info）、`regex: true`（matcher 按 Go 正则而非子串解释）、`part: header`（匹配响应头而非响应体）。`matcher` 默认大小写不敏感子串匹配
- **族名如何触发**：把族名与指纹命中的 `id`/`name`/`product`/`vendor`/`tags` 都规范化（小写、去掉 `-_. /`）后做子串比较，族名短于 3 字符不参与，避免噪声。所以族名写 `spring` 即可覆盖 `spring-boot-admin`、`lin-cms-spring-boot` 等
- **特殊键 `__always__`**：不依赖指纹、对所有目标都跑的探测项。上游指纹库 99.9% 的规则是根路径型，"应用是 Spring Boot 但没被指纹识别"是常态，因此把 Actuator / Swagger 这类**价值极高且请求很少**的路径放在这里。只应放这类路径，否则会吃掉请求预算
- 探测项也会在候选 base（如 `--base-path /oa`、指纹层推出的落地目录）下重试，以应对应用挂在子目录的情况；每个探测项最多试 2 个 base
- 站点为通配 200（软 404）时，换 base 无法区分，故主动限制 base 尝试次数并在 `Notes` 里说明
- probe 层自身开销上限：40 请求；指纹族探测项 ≤24；且始终受 httpx 的单目标总预算（100）约束

## 7. JS 审计（核心模块）

### 7.1 JS 获取

- 来源：首页 + 同域深度 1 爬取的页面
- 上限：JS 数量 ≤30/目标，单文件 ≤2MB（超大打包文件截断）
- 尝试请求 `.js.map` sourcemap（能还原源码，信息量远大于混淆 JS）
- URL 归一化：处理 `//static/js/...` 双斜杠等畸形

**实现要点（实测后补充）：**

- 深度 1 页面 ≤8 个、内联脚本 ≤12 段，与外部 JS 的 ≤30 分开计数（三者性质不同，合并计数会让某个来源挤掉其它来源）
- **URL 归一化策略**：`//host/path` 首段**像主机名**（含点、含端口、是 localhost）时按协议相对 URL 处理（`//cdn.example.com/x.js`）；首段不像主机名时视为被写坏的站内路径，归一化成 `/static/js/x.js`。`\/\/static\/js\/x.js` 这类 JS 转义写法先还原再走同一套判断
- 只分析 `http`/`https`，跳过 `data:`/`javascript:`/`mailto:`/`blob:`
- 内联脚本一并分析（`application/json` 也分析，内联配置里常藏密钥）；`text/template`、`text/x-handlebars-template` 等模板类型跳过，避免模板语法污染接口提取
- sourcemap **仅在含 `sourcesContent` 时**才收录——只有文件名的 map 没有源码，信息量还不如 minified JS

### 7.2 七类检测规则

| 类别 | 说明 | 级别 |
|---|---|---|
| 硬编码凭证 | `Authorization: Basic/Bearer`、`password:`/`secret:` 赋值；Basic 后 base64 **自动解码还原成 `user:pass` 展示** | 高危 |
| 云 AK/SK | 阿里云 AccessKeyId、腾讯云 SecretId、AWS `AKIA...`、华为云 | 高危 |
| Token | JWT（`eyJ` 开头，解码 header/payload 展示）、apiKey/appSecret 赋值 | 中危 |
| 私钥 | `-----BEGIN ... PRIVATE KEY-----` | 高危 |
| 内网信息 | 内网 IP（10/172.16/192.168）、`.internal`/`.corp` 域名 | 低危 |
| 接口路径 | 提取所有 URL 路径，喂语义层判危险度，**只展示不请求** | 信息 |
| 注释敏感信息 | JS 注释中的测试账号、内部文档地址 | 低危 |

- base64 最多嵌套解码 2 层；熵值 >4.0 才进入疑似密钥判断（防普通文本误报）
- 典型目标：能识别 `Authorization:"Basic YWRtaW46YWJjZEAxMjM0"` 并解码展示为 `admin:abcd@1234`

**实现要点（实测后补充）：**

- **熵值门槛按规则分级**：`>4.0` 用于"纯靠形态猜测"的场景（如 `accessKeyId: "<随机串>"`）；而 `password:`/`secret:`/`token:` 这类**带明确键名的赋值**本身已是高信号，真实短口令的熵天然低于 4.0（设计文档里的 `abcd@1234` 熵约 3.17），故改用 2.5~3.0 + 占位符黑名单控误报；**形态唯一**的规则（AWS `AKIA…`/阿里云 `LTAI…`/腾讯云 `AKID…`、`-----BEGIN … PRIVATE KEY-----`、JWT、`Authorization` 头）完全绕过熵值与占位符判断——形态本身就是证据
- 占位符过滤：含 `your_`/`xxxx`/`changeme`/`placeholder`/`example`/`sample`/`{{`/`${` 等字样，或整体是纯重复字符、常见弱口令（`password`/`123456`/`admin`）即视为占位符
- **内网 IP 段**：`10/8`、`172.16/12`（即 16~31）、`192.168/16`；内网域名后缀 `internal`/`corp`/`intranet`/`lan`/`local`
- **接口路径**：只提取绝不请求；按 `(路径, 偏移)` 跨正则去重后计数（避免 `fetch("/x")` 同时被两条正则命中而重复计数）；过滤静态资源后缀与 `/static/`、`/assets/`、`/node_modules/` 等噪声目录；按出现次数降序、有上限
- **七类规则的级别映射**：硬编码凭证/云 AK/SK/私钥 = 高危；Token = 中危；内网信息/注释敏感信息 = 低危；接口路径 = 信息
- 语义层只接收"需要复核"的类别（接口路径、注释、赋值类凭证、内网信息）；**私钥与云 AK 不外发**，减少真实密钥泄露面与外发量（见第 8 节）
- 注释类规则只作用于注释文本（`//` 与 `/* */`，且排除 `http://` 这类伪注释），不会因为代码字符串里出现"测试账号"字样而误报

## 8. 语义层（可降级）

- OpenAI 兼容 API，配置走配置文件 `llm` 段（见第 4 节）
- 只发送正则初筛后的可疑片段：疑似敏感字符串（带前后 50 字符上下文）+ 提取的接口路径
- 批量一次请求，要求结构化 JSON 返回：`[{item, is_sensitive, reason, confidence}]`
- 无 api_key / API 不可用时**静默降级**为纯正则模式，不影响其他功能
- README 必须明示：目标站点的 JS 片段会发送给第三方 API，存在数据外发风险

**实现要点（实测后补充）：**

- 复用 `httpx` 发请求（为其加了 POST body 支持），因此代理、超时、TLS 策略与扫描侧一致；语义层不做 QPS 限速
- "批量一次请求"落地为**按批合并**：单批默认 40 条、单次扫描最多外发 120 条（`MaxItems`/`MaxBatch` 可配），避免超过上下文长度或单次成本失控
- **宽容解析**模型输出：裸 JSON 数组、Markdown 代码块包裹、`{"results|items|data":[...]}` 三种形态都能吃下；确实解析不出结构化结果才报错并按"未判定"处理
- 单批失败不影响其它批；**未判定的条目在报告中退回纯正则结论**，不会因为语义层出错而丢结果
- 外发内容已经在 jsaudit 侧筛过：**私钥与云 AK 不外发**，只发需要复核的片段与接口路径
- 置信度钳制到 `[0,1]`，理由截断到 200 字符；模型返回未知/重复 item 时忽略

## 9. 并发与限速

- 目标级并发默认 10；单目标内部最多 3 并发；单目标 QPS ~5
- `--rate` 参数可调；超时 10s/请求；单目标总耗时上限 3 分钟

## 10. 输出

- 终端彩色输出（高危红色醒目标注）
- JSON 文件（机器可读，可管道给其他工具）
- HTML 报告（人工研判用，展示指纹、暴露面、JS 敏感信息汇总）

**实现要点（实测后补充）：**

- **统一严重级别**：`critical`/`high`/`medium`/`low`/`info`，中文展示为 严重/高危/中危/低危/信息；probe 的 `severity` 与 jsaudit 的级别都归一到这套取值，未知值按 `info` 处理
- 终端配色：严重=红底白字、高危=红、中危=黄、低危=青、信息=灰。**颜色由调用方控制**：设置 `NO_COLOR` 或输出被重定向时关闭，避免日志里混入 ANSI 转义。接口路径在终端只列前 20 条，其余指向 JSON/HTML 报告
- JSON：2 空格缩进 + 结尾换行，便于人工查看也便于管道；字段名稳定，便于下游工具依赖
- HTML：**完全自包含**（CSS 全部内联，不引用任何外部资源），离线可打开；用 `html/template` 自动转义——证据字段直接来自目标站点的响应内容，必须转义，否则报告自身会变成 XSS 载体
- 报告内每个目标按"最严重级别"排序展示，暴露面与 JS 发现都按严重度降序排列
- 输出文件默认写在项目目录内（`./reports/`），已加入 `.gitignore`

## 11. 代码结构

```
scanner/
├── cmd/scanner/main.go      # CLI 薄壳（flag 解析）
├── pkg/
│   ├── target/              # 目标解析：域名/IP:port → http+https 双协议探测
│   ├── httpx/               # HTTP 客户端池：跟随重定向、跳过证书验证、限速、404 基线、代理
│   ├── fingerprint/         # 指纹引擎：加载转换后的规则、子目录候选匹配
│   ├── convert/             # FingerprintHub nuclei YAML → 内部 JSON（服务 update 命令）
│   ├── probe/               # 漏洞点探测包：指纹→探测路径→内容匹配器
│   ├── jsaudit/             # JS 收集（深度1爬取+sourcemap）+ 七类规则提取 + base64 解码
│   ├── semantic/            # LLM 接口：OpenAI 兼容客户端，批量打分，可降级
│   ├── config/              # 配置文件加载与合并
│   └── report/              # JSON + HTML 报告
├── rules/                   # probe-packs.yaml、通用暴露面字典（go:embed）
├── fingerprints.json        # 转换后的指纹库（go:embed）
├── docs/
│   └── PROGRESS.md          # 开发进度文档（每次开发完成必须更新）
└── config.yaml.example      # 配置文件示例
```
