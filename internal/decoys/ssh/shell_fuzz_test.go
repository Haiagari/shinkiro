package ssh

import (
	"testing"
)

func FuzzVirtualFSExecute(f *testing.F) {
	seeds := []string{
		"whoami",
		"id",
		"pwd",
		"ls -la",
		"cat /etc/passwd",
		"uname -a",
		"curl http://evil.com",
		"rm -rf /",
		"",
		"   ",
		"cat /proc/cpuinfo",
		"find / -name *.conf",
		"echo $USER",
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, cmd string) {
		vfs := NewVirtualFS("root", "shinkiro-srv-prod01")
		_ = vfs.Execute(cmd)
	})
}
