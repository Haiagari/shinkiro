package ssh

import (
	"strings"
	"testing"
)

func TestVirtualFS_Commands(t *testing.T) {
	vfs := NewVirtualFS("root", "shinkiro-srv-prod01")

	// 1. Whoami
	if out := vfs.Execute("whoami"); out != "root\n" {
		t.Errorf("expected root\n, got %q", out)
	}

	// 2. ID
	if out := vfs.Execute("id"); !strings.Contains(out, "uid=0(root)") {
		t.Errorf("expected root uid in id output: %s", out)
	}

	// 3. Cat passwd
	if out := vfs.Execute("cat /etc/passwd"); !strings.Contains(out, "root:x:0:0:root") {
		t.Errorf("expected /etc/passwd contents: %s", out)
	}

	// 4. Cat .env honeytoken
	if out := vfs.Execute("cat /root/.env"); !strings.Contains(out, "AKIA_SHINKIRO_HONEY_TOKEN") {
		t.Errorf("expected honeytoken in .env: %s", out)
	}

	// 5. History
	if out := vfs.Execute("history"); !strings.Contains(out, "whoami") {
		t.Errorf("expected whoami in history: %s", out)
	}
}
