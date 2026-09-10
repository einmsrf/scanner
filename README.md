# scanner

Go 编写的单文件 Web 资产扫描 CLI：输入域名或 IP，自动补全 `http`/`https`、识别 Web 指纹、
按指纹探测已知暴露面、审计前端 JS 中的敏感信息与接口。

> ⚠️ **仅限授权测试。** 请只对自己拥有或已获得明确书面授权的目标使用本工具。

## 特性

- **目标解析**：支持 `域名`、`IP`、`IP:端口`、`域名:端口`、完整 URL（路径作为 base-path 提示）、
  `#` 注释行；默认 https 优先、失败降级 http，`--both` 可两个协议都扫
- **指纹识别**：内置 [FingerprintHub](https://github.com/0x727/FingerprintHub) 转换来的
  3300+ 条规则（word / regex / favicon），四层兜底匹配以应对部署目录被修改：
  重定向跟随 → 路径无关规则（body/header/favicon）→ 子目录候选 → `--base-path` 手动指定
- **暴露面探测**：按指纹族组织的探测包 + 20 条通用暴露面字典；
  **只做判活，不发送任何 payload**，每条路径都带内容匹配器，裸 200 不算命中，
  并用 404 基线过滤软 404 误报
- **JS 审计（核心）**：首页 + 同域深度 1 爬取、尝试 `.js.map` 还原源码；
  检测七类信息：硬编码凭证、云 AK/SK、Token、私钥、内网信息、接口路径、注释敏感信息；
  `Authorization: Basic` 的 base64 会自动解码还原成 `user:pass` 展示，JWT 会解码 header/payload
- **语义层（可降级）**：把正则初筛后的可疑片段批量送给 OpenAI 兼容接口复核，降低误报；
  未配置 `api_key` 时静默降级为纯正则模式
- **输出**：终端彩色摘要、JSON（机器可读）、自包含 HTML 报告（人工研判）

## 安装 / 构建

```bash
git clone https://github.com/einmsrf/scanner.git
cd scanner
go build -o scanner ./cmd/scanner        # Windows: go build -o scanner.exe ./cmd/scanner
```

单文件发布构建（无 CGO 依赖）：

```bash
GOARCH=amd64 CGO_ENABLED=0 go build -o scanner ./cmd/scanner
```

## 快速开始

```bash
# 单个目标
./scanner -u example.com

# 批量扫描
./scanner -l targets.txt

# 应用部署在子目录 /oa，且两个协议都要扫
./scanner -u example.com --both --base-path /oa

# 只看结果、不写报告文件；或把 JSON 直接管道给其他工具
./scanner -u example.com --quiet
./scanner -u example.com --json - | jq '.summary'

# 更新指纹库（从 GitHub 拉取 FingerprintHub 重新转换）
./scanner update
./scanner update --source-dir /path/to/FingerprintHub   # 离线 / 锁定版本
```

`targets.txt` 示例：

```
# 一行一个目标，# 开头为注释，空行忽略
example.com
1.2.3.4
10.0.0.5:8080
https://app.example.com/portal
```

## 命令行选项

| 选项 | 说明 |
|---|---|
| `-u, --url <目标>` | 单个目标 |
| `-l, --list <文件>` | 目标列表文件 |
| `--both` | `http` 与 `https` 都扫描 |
| `--base-path <路径>` | 手动指定部署 base 路径（如 `/oa`） |
| `--rate <float>` | 单目标 QPS 上限；`-1` 表示不限速（默认取配置，5） |
| `--concurrency <n>` | 目标级并发（默认取配置，10） |
| `--timeout <dur>` | 单请求超时（默认 `10s`） |
| `--target-timeout <dur>` | 单目标总耗时上限（默认 `3m`） |
| `--max-requests <n>` | 单目标请求预算上限（默认 100） |
| `--proxy <url>` | 代理（默认取配置或 `HTTPS_PROXY`） |
| `--out <目录>` | 报告输出目录（默认 `reports`） |
| `--json <路径>` | JSON 报告路径；`-` 表示输出到标准输出 |
| `--html <路径>` | HTML 报告路径 |
| `--no-js` | 跳过 JS 审计 |
| `--no-probe` | 跳过暴露面探测 |
| `--no-semantic` | 不使用语义层 |
| `--verify-tls` | 校验证书（默认跳过，目标多为自签） |
| `--color` / `--no-color` | 强制开/关彩色（管道与 `NO_COLOR` 下自动关闭） |
| `--quiet` | 不输出终端报告 |
| `--verbose` | 输出更多细节 |
| `--config <路径>` | 配置文件路径 |

完整说明见 `./scanner --help`。

## 配置文件

查找顺序：`--config` 指定 > 当前目录 `config.yaml` > 可执行文件同目录 `config.yaml`。
缺失则使用默认值。命令行参数优先级高于配置文件。

```bash
cp config.yaml.example config.yaml
```

```yaml
llm:
  base_url: "https://api.deepseek.com/v1"   # 任何 OpenAI 兼容接口
  api_key: ""                               # 留空则语义层自动降级为纯正则模式
  model: "deepseek-chat"
  timeout: 30s

proxy: ""                                   # 如 "http://127.0.0.1:7890"；留空则用 HTTPS_PROXY

scan:
  concurrency: 10      # 目标级并发
  qps: 5               # 单目标每秒请求数上限
  timeout: 10s         # 单请求超时
```

`config.yaml` 含 `api_key`，已在 `.gitignore` 中，不会入库。

## ⚠️ 数据外发风险提示（启用语义层前必读）

**启用语义层后，本工具会把从目标站点 JS 中提取的内容发送给第三方 API（你配置的 `llm.base_url`）。**
具体外发内容包括：

- 正则初筛后的**可疑片段**（含敏感值前后各 50 字符上下文）
- 从 JS 中提取到的**接口路径**

已做的收敛措施：

- **私钥与云 AK/SK 不会被外发**——这两类形态唯一、确定性高，无需语义复核，也不该离开你的机器
- 单次扫描外发条目数有上限（默认 120 条，单批 40 条），避免意外的数据批量外泄
- 留空 `llm.api_key` 即完全不外发任何数据（纯本地正则模式）

如果目标站点的 JS 属于敏感数据，或你所在环境不允许数据出网，请**不要配置 `api_key`**，
或使用 `--no-semantic`。

## 行为边界（安全设计）

本工具刻意做成"只读"：

- **绝不主动请求 JS 中发现的接口。** 接口路径只被提取、展示与送语义层判危险度，不会被访问
  （测试中有专门断言：扫描过程中服务端收到的请求路径里不包含任何 `/api/*`）
- **暴露面探测只做判活，不发送任何 payload。** 每条探测路径必须带内容匹配器，
  仅当返回体/响应头出现特征串才算命中，裸 200 不算
- **不做目录爆破**：不内置 `/oa`、`/system` 之类的猜测字典；
  子目录候选只从落地页自身暴露的链接中提取
- 默认跳过 TLS 证书校验（大量目标为自签证书或 IP 直连）

## 输出

- **终端**：按级别着色（严重=红底白字、高危=红、中危=黄、低危=青），结尾给出汇总统计。
  输出被重定向或设置了 `NO_COLOR` 时自动关闭颜色
- **JSON**（`reports/scan-<时间戳>.json`）：2 空格缩进，字段稳定，便于下游工具消费
- **HTML**（`reports/scan-<时间戳>.html`）：完全自包含（CSS 内联、不引用任何外部资源），
  离线可打开；所有来自目标站点的内容都经过转义

## 项目结构

```
scanner/
├── cmd/scanner/            # CLI：main.go（flag/配置）、scan.go（编排）、update.go（更新指纹库）
├── pkg/
│   ├── target/             # 目标解析、协议探测、落地页与候选 base
│   ├── httpx/              # HTTP 客户端：重定向/TLS/限速/预算/404 基线/代理
│   ├── fingerprint/        # 指纹模型、mmh3+md5、四层兜底匹配引擎
│   ├── convert/            # FingerprintHub nuclei YAML → 内部 JSON
│   ├── probe/              # 指纹族探测包 + 通用字典 + 内容匹配
│   ├── jsaudit/            # JS 收集 + 七类规则 + base64/JWT 解码
│   ├── semantic/           # OpenAI 兼容语义层（可降级）
│   ├── config/             # 配置加载与合并
│   └── report/             # 统一级别模型 + 终端/JSON/HTML 输出
├── rules/                  # probe-packs.yaml + exposure.yaml（go:embed）
├── fingerprints.json       # 转换后的指纹库（go:embed）
├── config.yaml.example     # 配置文件示例
├── docs/PROGRESS.md        # 开发进度
└── DESIGN.md               # 设计文档（开发依据）
```

## 开发

```bash
go vet ./...
go test ./...              # 本机无 gcc，-race 由 CI 执行
go test -count=3 ./...     # 重复跑以补充竞态排查
```

CI（`.github/workflows/ci.yml`）在每次 push/PR 到 `main` 时于 `windows-latest` 上
运行 `go vet`、`go test -race -count=1` 与 `go build`。

设计与进度分别见 [DESIGN.md](DESIGN.md) 与 [docs/PROGRESS.md](docs/PROGRESS.md)。
