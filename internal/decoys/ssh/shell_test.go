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

	// 6. cd and pwd navigation
	_ = vfs.Execute("cd /etc")
	if out := vfs.Execute("pwd"); out != "/etc\n" {
		t.Errorf("expected /etc pwd, got %q", out)
	}

	// 7. head command
	if out := vfs.Execute("head /etc/passwd"); !strings.Contains(out, "root:x:0:0") {
		t.Errorf("expected head output, got: %s", out)
	}

	// 8. find command
	if out := vfs.Execute("find / -name *.conf"); !strings.Contains(out, "/etc/resolv.conf") {
		t.Errorf("expected find output to contain resolv.conf, got: %s", out)
	}

	// 9. ls -la
	if out := vfs.Execute("ls -la"); !strings.Contains(out, "total") {
		t.Errorf("expected ls -la output, got: %s", out)
	}

	// 10. grep
	if out := vfs.Execute("grep root /etc/passwd"); !strings.Contains(out, "root:x:0:0") {
		t.Errorf("expected grep output to contain root user, got: %s", out)
	}

	// 11. sudo whoami
	if out := vfs.Execute("sudo whoami"); out != "root\n" {
		t.Errorf("expected sudo whoami to output root, got: %s", out)
	}

	// 12. df & free
	if out := vfs.Execute("df"); !strings.Contains(out, "/dev/sda1") {
		t.Errorf("expected df output, got: %s", out)
	}
	if out := vfs.Execute("free"); !strings.Contains(out, "Mem:") {
		t.Errorf("expected free output, got: %s", out)
	}
}
