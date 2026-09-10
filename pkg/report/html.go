package report

import (
	"bytes"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// WriteHTMLFile 输出自包含的 HTML 报告（人工研判用）。
// 不引用任何外部资源（CSS/JS 全部内联），因此离线也能正常打开。
func (r *Report) WriteHTMLFile(path string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return r.WriteHTML(f)
}

// WriteHTML 渲染 HTML 报告。
func (r *Report) WriteHTML(w interface{ Write([]byte) (int, error) }) error {
	tmpl, err := template.New("report").Funcs(templateFuncs).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, r); err != nil {
		return err
	}
	// 兜底：目标站点可能返回非 UTF-8 字节（GBK 页面很常见），
	// 一旦混入就会让整个 HTML 文件无法解码，这里统一规整为合法 UTF-8。
	out := buf.String()
	if !utf8.ValidString(out) {
		out = strings.ToValidUTF8(out, "\uFFFD")
	}
	_, err = io.WriteString(w, out)
	return err
}

var templateFuncs = template.FuncMap{
	"sevRank":    SeverityRank,
	"sevDisplay": SeverityDisplay,
	"sevClass": func(s string) string {
		switch SeverityRank(s) {
		case 0:
			return "sev-critical"
		case 1:
			return "sev-high"
		case 2:
			return "sev-medium"
		case 3:
			return "sev-low"
		default:
			return "sev-info"
		}
	},
	"viaDisplay": viaDisplay,
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>scanner 扫描报告 — {{.GeneratedAt}}</title>
<style>
  :root {
    --bg:#0f1115; --panel:#171a21; --line:#2a2f3a; --fg:#e6e8ee; --dim:#98a2b3;
    --critical:#ff4d4f; --high:#ff7a45; --medium:#fadb14; --low:#40a9ff; --info:#8c8c8c;
    --ok:#52c41a;
  }
  * { box-sizing:border-box; }
  body { margin:0; padding:24px; background:var(--bg); color:var(--fg);
         font:14px/1.6 -apple-system,"Segoe UI","Microsoft YaHei",system-ui,sans-serif; }
  h1 { font-size:20px; margin:0 0 4px; }
  h2 { font-size:17px; margin:0 0 10px; padding-bottom:6px; border-bottom:1px solid var(--line); }
  h3 { font-size:14px; margin:18px 0 8px; color:var(--dim); font-weight:600;
       text-transform:uppercase; letter-spacing:.04em; }
  .meta { color:var(--dim); font-size:13px; margin-bottom:20px; }
  .panel { background:var(--panel); border:1px solid var(--line); border-radius:10px;
           padding:16px; margin-bottom:18px; }
  .summary { display:flex; flex-wrap:wrap; gap:10px 26px; }
  .summary div { min-width:120px; }
  .summary .k { color:var(--dim); font-size:12px; }
  .summary .v { font-size:20px; font-weight:600; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--line);
          vertical-align:top; word-break:break-word; }
  th { color:var(--dim); font-weight:600; font-size:12px; }
  code { font-family:ui-monospace,Consolas,"Courier New",monospace; font-size:12px;
         background:#0b0d11; padding:1px 5px; border-radius:4px; color:#c9d1d9; }
  .badge { display:inline-block; padding:1px 7px; border-radius:10px; font-size:11px;
           font-weight:600; color:#111; white-space:nowrap; }
  .sev-critical { background:var(--critical); color:#fff; }
  .sev-high     { background:var(--high); color:#fff; }
  .sev-medium   { background:var(--medium); }
  .sev-low      { background:var(--low); color:#fff; }
  .sev-info     { background:var(--info); color:#fff; }
  .dim { color:var(--dim); }
  .err { color:var(--critical); }
  .ok  { color:var(--ok); }
  .tag { display:inline-block; margin:0 6px 6px 0; padding:2px 9px; border-radius:12px;
         background:#22262f; border:1px solid var(--line); font-size:12px; }
  .evidence { color:var(--dim); font-size:12px; }
  details summary { cursor:pointer; color:var(--dim); font-size:12px; }
  .ep { display:inline-block; margin:0 8px 6px 0; font-size:12px; }
  .note { color:var(--dim); font-size:12px; }
  footer { color:var(--dim); font-size:12px; margin-top:26px; text-align:center; }
</style>
</head>
<body>

<h1>{{.Tool}} 扫描报告</h1>
<div class="meta">
  版本 {{.Version}} · 生成于 {{.GeneratedAt}}
  {{if .Fingerprints}}<br>指纹库：{{.Fingerprints}}{{end}}
  {{if .Semantic}}<br>语义层：{{.Semantic}}{{end}}
  {{if .Args}}<br>命令行：<code>{{.Args}}</code>{{end}}
</div>

<div class="panel">
  <h2>汇总</h2>
  <div class="summary">
    <div><div class="k">目标</div><div class="v">{{.Summary.Targets}}</div></div>
    <div><div class="k">成功 / 失败</div><div class="v"><span class="ok">{{.Summary.TargetsOK}}</span> / <span class="err">{{.Summary.TargetsFailed}}</span></div></div>
    <div><div class="k">指纹命中</div><div class="v">{{.Summary.Fingerprints}}</div></div>
    <div><div class="k">暴露面</div><div class="v">{{.Summary.Exposures}}</div></div>
    <div><div class="k">JS 敏感信息</div><div class="v">{{.Summary.JSFindings}}</div></div>
    <div><div class="k">接口路径</div><div class="v">{{.Summary.Endpoints}}</div></div>
    <div><div class="k">请求次数</div><div class="v">{{.Summary.Requests}}</div></div>
    <div><div class="k">耗时</div><div class="v">{{.Summary.Duration}}</div></div>
  </div>
  <h3>级别统计</h3>
  <div>
    {{if .Summary.Critical}}<span class="badge sev-critical">严重 {{.Summary.Critical}}</span>{{end}}
    {{if .Summary.High}}<span class="badge sev-high">高危 {{.Summary.High}}</span>{{end}}
    {{if .Summary.Medium}}<span class="badge sev-medium">中危 {{.Summary.Medium}}</span>{{end}}
    {{if .Summary.Low}}<span class="badge sev-low">低危 {{.Summary.Low}}</span>{{end}}
    {{if .Summary.Info}}<span class="badge sev-info">信息 {{.Summary.Info}}</span>{{end}}
    {{if eq .Summary.Critical 0}}{{if eq .Summary.High 0}}{{if eq .Summary.Medium 0}}{{if eq .Summary.Low 0}}<span class="ok">未发现风险项</span>{{end}}{{end}}{{end}}{{end}}
  </div>
</div>

{{range .Targets}}
<div class="panel">
  <h2>{{.Target}}</h2>
  {{if not .OK}}
    <p class="err">✗ 扫描失败：{{.Error}}</p>
  {{else}}
  <div class="meta">
    {{if .URL}}<code>{{.URL}}</code>{{end}}
    · HTTP <span {{if ge .Status 400}}class="err"{{end}}>{{.Status}}</span>
    {{if .Server}} · server: {{.Server}}{{end}}
    {{if .Duration}} · 耗时 {{.Duration}}{{end}}
    · 请求 {{.Requests}} 次
    {{if .HighestSeverity}} · 最高级别 <span class="badge {{sevClass .HighestSeverity}}">{{sevDisplay .HighestSeverity}}</span>{{end}}
  </div>
  {{if .Title}}<p>标题：{{.Title}}</p>{{end}}

  <h3>指纹（{{len .Fingerprints}}）</h3>
  {{if .Fingerprints}}
  <table>
    <tr><th>产品</th><th>命中方式</th><th>依据</th><th>Vendor</th></tr>
    {{range .Fingerprints}}
    <tr>
      <td>{{.Display}}</td>
      <td>{{if .Via}}<span class="dim">{{viaDisplay .Via}}</span>{{end}}</td>
      <td class="evidence">{{.Evidence}}</td>
      <td class="dim">{{.Vendor}}</td>
    </tr>
    {{end}}
  </table>
  {{else}}<p class="note">未命中任何指纹。</p>{{end}}

  <h3>暴露面（{{len .Exposures}}）</h3>
  {{if .Exposures}}
  <table>
    <tr><th>级别</th><th>名称</th><th>路径</th><th>证据</th></tr>
    {{range .Exposures}}
    <tr>
      <td><span class="badge {{sevClass .Severity}}">{{sevDisplay .Severity}}</span></td>
      <td>{{.Name}}</td>
      <td><code>{{.Path}}</code>{{if .Family}} <span class="dim">〔{{.Family}}〕</span>{{end}}</td>
      <td class="evidence">{{.Evidence}}</td>
    </tr>
    {{end}}
  </table>
  {{else}}<p class="note">未发现暴露面。</p>{{end}}

  {{with .JS}}
  <h3>JS 审计</h3>
  <p class="note">分析文件 {{.AssetsScanned}} 个{{if .SourceMapHits}}（其中 sourcemap 还原 {{.SourceMapHits}} 个）{{end}}，共 {{len .Findings}} 条敏感信息、{{len .Endpoints}} 个接口路径。</p>

  {{if .Findings}}
  <table>
    <tr><th>级别</th><th>类别</th><th>位置</th><th>内容</th><th>语义复核</th></tr>
    {{range .Findings}}
    <tr>
      <td><span class="badge {{sevClass .Severity}}">{{sevDisplay .Severity}}</span></td>
      <td>{{.Category}}</td>
      <td class="dim">{{.File}}{{if .Line}}:{{.Line}}{{end}}{{if .Source}} <span class="dim">({{.Source}})</span>{{end}}</td>
      <td>
        {{if .Decoded}}<code>{{.Decoded}}</code><div class="evidence">解码自 base64/JWT</div>
        {{else if .Value}}<code>{{.Value}}</code>{{end}}
        {{if .Note}}<div class="evidence">{{.Note}}</div>{{end}}
        {{if .Context}}<details><summary>上下文</summary><div class="evidence"><code>{{.Context}}</code></div></details>{{end}}
      </td>
      <td>
        {{if .Semantic}}{{if .Semantic.Judged}}
          {{if .Semantic.IsSensitive}}<span class="badge sev-high">确认敏感</span>{{else}}<span class="dim">疑似误报</span>{{end}}
          <div class="evidence">置信度 {{printf "%.2f" .Semantic.Confidence}}{{if .Semantic.Reason}} · {{.Semantic.Reason}}{{end}}</div>
        {{else}}<span class="dim">—</span>{{end}}{{else}}<span class="dim">未启用</span>{{end}}
      </td>
    </tr>
    {{end}}
  </table>
  {{end}}

  {{if .Endpoints}}
  <h3>接口路径（{{len .Endpoints}}，仅展示不请求）</h3>
  <div>
    {{range .Endpoints}}<span class="tag ep">{{if .Semantic}}{{if .Semantic.Judged}}{{if .Semantic.IsSensitive}}<span class="badge sev-high" title="{{.Semantic.Reason}}">高危接口</span> {{end}}{{end}}{{end}}<code>{{.Path}}</code>{{if gt .Count 1}} <span class="dim">×{{.Count}}</span>{{end}}</span>{{end}}
  </div>
  {{end}}

  {{if .Notes}}<details><summary>收集说明（{{len .Notes}}）</summary>{{range .Notes}}<div class="note">· {{.}}</div>{{end}}</details>{{end}}
  {{end}}

  {{if .Notes}}<details><summary>备注（{{len .Notes}}）</summary>{{range .Notes}}<div class="note">· {{.}}</div>{{end}}</details>{{end}}
  {{end}}
</div>
{{end}}

<footer>{{.Tool}} {{.Version}} · 报告由本工具自动生成，请人工复核后再采取处置措施。</footer>
</body>
</html>
`
