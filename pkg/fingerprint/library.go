package fingerprint

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// DefaultDiskPaths 是运行时优先尝试的磁盘指纹库路径。
// scanner update 重新生成 fingerprints.json 后无需重新编译即可生效。
var DefaultDiskPaths = []string{"fingerprints.json"}

// ParseLibrary 解析指纹库 JSON 并做基本校验。
func ParseLibrary(data []byte) (*Library, error) {
	if len(data) == 0 {
		return nil, errors.New("fingerprint: 指纹库数据为空")
	}
	var lib Library
	if err := json.Unmarshal(data, &lib); err != nil {
		return nil, fmt.Errorf("fingerprint: 指纹库 JSON 解析失败: %w", err)
	}
	valid := make([]Rule, 0, len(lib.Rules))
	for _, r := range lib.Rules {
		if strings.TrimSpace(r.ID) == "" || len(r.Matchers) == 0 {
			continue
		}
		if len(r.Paths) == 0 {
			r.Paths = []string{"/"}
		}
		valid = append(valid, r)
	}
	if len(valid) == 0 {
		return nil, errors.New("fingerprint: 指纹库不含任何有效规则")
	}
	lib.Rules = valid
	lib.Count = len(valid)
	return &lib, nil
}

// Load 加载指纹库：先按顺序尝试磁盘路径（PATH 语义的本地覆盖），
// 全部不可用时回退到 embedData（通常是编译进二进制的版本）。
// 返回的第二个值为人类可读的来源描述，用于报告与日志。
func Load(embedData []byte, diskPaths ...string) (*Library, string, error) {
	if len(diskPaths) == 0 {
		diskPaths = DefaultDiskPaths
	}
	var firstErr error
	for _, p := range diskPaths {
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			if !os.IsNotExist(err) && firstErr == nil {
				firstErr = fmt.Errorf("fingerprint: 读取 %s 失败: %w", p, err)
			}
			continue
		}
		lib, err := ParseLibrary(data)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("fingerprint: 解析 %s 失败: %w", p, err)
			}
			continue
		}
		return lib, fmt.Sprintf("%s（%d 条，生成于 %s）", p, lib.Count, lib.GeneratedAt), nil
	}

	lib, err := ParseLibrary(embedData)
	if err != nil {
		if firstErr != nil {
			return nil, "", fmt.Errorf("%w；内置指纹库也不可用: %v", firstErr, err)
		}
		return nil, "", err
	}
	return lib, fmt.Sprintf("内置指纹库（%d 条，生成于 %s）", lib.Count, lib.GeneratedAt), nil
}

// Product 返回适合展示的产品名，缺失时回退到 Name / ID。
func (r Rule) ProductOrName() string {
	for _, s := range []string{r.Product, r.Name, r.ID} {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return r.ID
}
