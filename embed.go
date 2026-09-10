// Package scanner 只承载编译期嵌入的资源文件，业务逻辑全部在 pkg/ 下。
//
// 之所以放在模块根目录：go:embed 只能引用同目录或子目录的文件，而指纹库与
// 规则文件按 DESIGN.md 第 11 节位于仓库根目录。
package scanner

import _ "embed"

// FingerprintsJSON 是 pkg/convert 从 FingerprintHub 模板转换出的指纹库。
// 可通过 `scanner update` 重新生成；运行时若在磁盘上找到更新的同名文件，
// 会优先使用磁盘版本（见 pkg/fingerprint.Load），因此更新无需重新编译。
//
//go:embed fingerprints.json
var FingerprintsJSON []byte

// ProbePacksYAML 是按指纹族组织的漏洞点探测包（只判活，不发 payload）。
//
//go:embed rules/probe-packs.yaml
var ProbePacksYAML []byte

// ExposureYAML 是对所有目标都跑的通用暴露面字典。
//
//go:embed rules/exposure.yaml
var ExposureYAML []byte
