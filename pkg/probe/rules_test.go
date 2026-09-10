package probe

import (
	"os"
	"testing"

	"github.com/einmsrf/scanner/pkg/fingerprint"
)

// 校验仓库里真实的规则文件：文件缺失则跳过（CI 首次构建时可能尚未生成）。
func TestRealRuleFilesParseAndValidate(t *testing.T) {
	packsYAML, err := os.ReadFile("../../rules/probe-packs.yaml")
	if err != nil {
		t.Skipf("未找到 rules/probe-packs.yaml，跳过: %v", err)
	}
	exposureYAML, err := os.ReadFile("../../rules/exposure.yaml")
	if err != nil {
		t.Skipf("未找到 rules/exposure.yaml，跳过: %v", err)
	}

	lib, err := Load(packsYAML, exposureYAML)
	if err != nil {
		t.Fatalf("规则文件校验失败: %v", err)
	}

	// DESIGN.md 第 6 节：通用暴露面字典 ≤20 条。
	if len(lib.Generic) == 0 {
		t.Error("通用暴露面字典为空")
	}
	if len(lib.Generic) > 20 {
		t.Errorf("通用暴露面字典 %d 条，超过设计上限 20 条", len(lib.Generic))
	}
	if len(lib.Always) == 0 {
		t.Error("__always__ 族为空")
	}
	if lib.PackCount() < 15 {
		t.Errorf("指纹族只有 %d 个，偏少", lib.PackCount())
	}
	for _, f := range lib.Families() {
		if f == AlwaysFamily {
			t.Error("__always__ 不应出现在普通族列表里")
		}
	}

	// 每条探测项都必须有 matcher（validate 已强制，这里再兜底核对）。
	check := func(owner string, specs []Spec) {
		for _, s := range specs {
			if s.Matcher == "" {
				t.Errorf("%s 的 %s 缺少 matcher", owner, s.Path)
			}
			if s.Path == "" || s.Path[0] != '/' {
				t.Errorf("%s 的路径 %q 未规范化", owner, s.Path)
			}
			if s.Regex && s.re == nil {
				t.Errorf("%s 的正则 %q 未编译", owner, s.Matcher)
			}
		}
	}
	check(AlwaysFamily, lib.Always)
	check("generic", lib.Generic)
	for _, f := range lib.Families() {
		check(f, lib.Pack(f))
	}
	t.Logf("规则文件: %d 个指纹族、%d 条 __always__、%d 条通用字典，共 %d 条探测项",
		lib.PackCount(), len(lib.Always), len(lib.Generic), lib.SpecCount())
}

// 每个族名都必须能真的被指纹库里的规则触发，否则那个包永远不会运行。
func TestEveryFamilyIsTriggerableByRealFingerprints(t *testing.T) {
	packsYAML, err := os.ReadFile("../../rules/probe-packs.yaml")
	if err != nil {
		t.Skipf("未找到 rules/probe-packs.yaml，跳过: %v", err)
	}
	fpData, err := os.ReadFile("../../fingerprints.json")
	if err != nil {
		t.Skipf("未找到 fingerprints.json，跳过: %v", err)
	}
	lib, err := ParseProbePacks(packsYAML)
	if err != nil {
		t.Fatalf("ParseProbePacks: %v", err)
	}
	fpLib, err := fingerprint.ParseLibrary(fpData)
	if err != nil {
		t.Fatalf("ParseLibrary: %v", err)
	}

	matches := make([]fingerprint.Match, 0, len(fpLib.Rules))
	for i := range fpLib.Rules {
		matches = append(matches, fingerprint.Match{Rule: &fpLib.Rules[i]})
	}
	selected := map[string]bool{}
	for _, f := range lib.SelectFamilies(matches) {
		selected[f] = true
	}

	var dead []string
	for _, f := range lib.Families() {
		if !selected[f] {
			dead = append(dead, f)
		}
	}
	if len(dead) > 0 {
		t.Errorf("以下指纹族永远无法被触发（族名与指纹库对不上，包会形同虚设）: %v", dead)
	}
}
