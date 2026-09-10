# 开发进度

> 每次开发完成（一个模块或一个开发会话结束）必须更新本文档。规则见 DESIGN.md 第 2.2 节。

## 总体进度

- [ ] `httpx` — HTTP 客户端池：跟随重定向、跳过证书验证、限速、404 基线、代理
- [ ] `target` — 目标解析：域名/IP:port → http+https 双协议探测
- [ ] `config` — 配置文件加载与合并
- [ ] `convert` — FingerprintHub nuclei YAML → 内部 JSON（服务 update 命令）
- [ ] `fingerprint` — 指纹引擎：规则加载、四层兜底匹配（重定向/路径无关/子目录候选/手动 base-path）
- [ ] `probe` — 漏洞点探测包：指纹→探测路径→内容匹配器 + 通用暴露面字典
- [ ] `jsaudit` — JS 收集（深度1爬取+sourcemap）+ 七类规则提取 + base64 解码
- [ ] `semantic` — LLM 语义层：OpenAI 兼容客户端，批量打分，可降级
- [ ] `report` — JSON + HTML 报告
- [ ] CLI 组装与联调

## 开发日志

### 2026-09-10 — 项目重置，重新开发

- 应使用者要求清除上一轮全部开发成果：代码（`pkg/`、`go.mod`、`go.sum`）、git 历史、远程 tag 已全部清空
- 保留：DESIGN.md（设计定稿，仍是开发唯一依据）、README.md、.gitignore、本文档
- 当前进度：零代码，从第一个模块重新开始
- 待办：按 DESIGN.md 第 2.2 节顺序开工，第一步实现 `httpx`
