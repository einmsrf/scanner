package report

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// JSONBytes 返回缩进后的 JSON（便于人工查看，也便于管道处理）。
//
// 注意：方法名不能叫 MarshalJSON——那会让 *Report 实现 json.Marshaler，
// 而本方法内部又要调用 json.Marshal，形成无限递归。
func (r *Report) JSONBytes() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// WriteJSON 把报告写成 JSON。
func (r *Report) WriteJSON(w interface{ Write([]byte) (int, error) }) error {
	b, err := r.JSONBytes()
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// WriteJSONFile 写出 JSON 文件，自动创建父目录。
// 路径由调用方保证在项目目录内（见 DESIGN.md 第 2.0 节铁律）。
func (r *Report) WriteJSONFile(path string) error {
	b, err := r.JSONBytes()
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, b, 0o644)
}
