package ssh

import (
	"fmt"
	"strings"
	"time"
)

// VirtualFS represents an in-memory Unix environment for the decoy shell
type VirtualFS struct {
	hostname    string
	username    string
	cwd         string
	history     []string
	env         map[string]string
	files       map[string]string
}

// NewVirtualFS builds an authentic, realistic Linux filesystem in memory
func NewVirtualFS(username, hostname string) *VirtualFS {
	if hostname == "" {
		hostname = "shinkiro-srv-prod01"
	}
	if username == "" {
		username = "root"
	}

	fs := &VirtualFS{
		hostname: hostname,
		username: username,
		cwd:      "/root",
		history:  make([]string, 0),
		env: map[string]string{
			"USER":     username,
			"HOME":     "/root",
			"SHELL":    "/bin/bash",
			"TERM":     "xterm-256color",
			"PATH":     "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"HOSTNAME": hostname,
		},
		files: make(map[string]string),
	}

	// Seed realistic system files
	fs.files["/etc/passwd"] = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nadmin:x:1000:1000:Admin User,,,:/home/admin:/bin/bash\ndeploy:x:1001:1001:Deployment Service:/home/deploy:/bin/bash\n"
	fs.files["/etc/shadow"] = "root:$6$rounds=4096$eK1$yK29mO9...:19700:0:99999:7:::\nadmin:$6$rounds=4096$zP8$aB81...:19700:0:99999:7:::\n"
	fs.files["/etc/os-release"] = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\nID=debian\nHOME_URL=\"https://www.debian.org/\"\nSUPPORT_URL=\"https://www.debian.org/support\"\nBUG_REPORT_URL=\"https://bugs.debian.org/\"\n"
	fs.files["/etc/hostname"] = hostname + "\n"
	fs.files["/etc/resolv.conf"] = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
	fs.files["/etc/hosts"] = "127.0.0.1\tlocalhost\n127.0.1.1\t" + hostname + "\n10.0.4.15\tprod-db-internal\n"
	fs.files["/proc/version"] = "Linux version 6.6.137+deb12u1-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.6.137-1\n"
	fs.files["/proc/cpuinfo"] = "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 142\nmodel name\t: Intel(R) Xeon(R) Platinum 8275CL CPU @ 3.00GHz\nstepping\t: 10\nmicrocode\t: 0xffffffff\ncpu MHz\t\t: 2999.998\ncache size\t: 36608 KB\nphysical id\t: 0\nsiblings\t: 2\ncore id\t\t: 0\ncpu cores\t: 2\n"
	fs.files["/var/log/auth.log"] = "Sep  5 12:30:14 " + hostname + " sshd[812]: Accepted publickey for root from 192.168.1.100 port 49152 ssh2\nSep  5 13:00:01 " + hostname + " CRON[942]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)\n"

	// Seed decoy credentials & honey tokens
	fs.files["/root/.env"] = "AWS_ACCESS_KEY_ID=AKIA_SHINKIRO_HONEY_TOKEN_01\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY_SHINKIRO\nPROD_DB_URL=postgres://prod_user:SuperSecretP@ss2026@10.0.4.15:5432/finance\nVAULT_TOKEN=s.shinkiro_canary_vault_root_token\n"
	fs.files["/root/.bash_history"] = "sudo apt-get update\ndocker ps\ncurl -s https://checkip.amazonaws.com\ncat /root/.env\nsystemctl restart nginx\n"
	fs.files["/etc/nginx/nginx.conf"] = "events { worker_connections 1024; }\nhttp {\n    server {\n        listen 80;\n        server_name localhost;\n        location / { proxy_pass http://127.0.0.1:8080; }\n    }\n}\n"

	return fs
}

// Prompt renders a standard bash prompt string
func (fs *VirtualFS) Prompt() string {
	char := "$"
	if fs.username == "root" {
		char = "#"
	}
	return fmt.Sprintf("%s@%s:%s%s ", fs.username, fs.hostname, fs.cwd, char)
}

// Execute parses and returns synthetic command output
func (fs *VirtualFS) Execute(cmdLine string) string {
	cmdLine = strings.TrimSpace(cmdLine)
	if cmdLine == "" {
		return ""
	}

	fs.history = append(fs.history, cmdLine)
	parts := strings.Fields(cmdLine)
	binary := parts[0]

	switch binary {
	case "id":
		if fs.username == "root" {
			return "uid=0(root) gid=0(root) groups=0(root)\n"
		}
		return "uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)\n"
	case "whoami":
		return fs.username + "\n"
	case "hostname":
		return fs.hostname + "\n"
	case "uname":
		if len(parts) > 1 && parts[1] == "-a" {
			return fmt.Sprintf("Linux %s 6.6.137+deb12u1-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.6.137-1 (2026-08-15) x86_64 GNU/Linux\n", fs.hostname)
		}
		return "Linux\n"
	case "pwd":
		return fs.cwd + "\n"
	case "cd":
		if len(parts) < 2 || parts[1] == "~" {
			fs.cwd = "/root"
			return ""
		}
		dest := parts[1]
		if dest == ".." {
			if fs.cwd != "/" {
				lastSlash := strings.LastIndex(fs.cwd, "/")
				if lastSlash == 0 {
					fs.cwd = "/"
				} else if lastSlash > 0 {
					fs.cwd = fs.cwd[:lastSlash]
				}
			}
			return ""
		}
		if !strings.HasPrefix(dest, "/") {
			if fs.cwd == "/" {
				dest = "/" + dest
			} else {
				dest = fs.cwd + "/" + dest
			}
		}
		dest = strings.TrimRight(dest, "/")
		if dest == "" {
			dest = "/"
		}
		fs.cwd = dest
		return ""
	case "uptime":
		return fmt.Sprintf(" %s up 42 days,  3:14,  1 user,  load average: 0.12, 0.08, 0.05\n", time.Now().Format("15:04:05"))
	case "ps":
		return "  PID TTY          TIME CMD\n    1 ?        00:00:03 systemd\n  482 ?        00:00:00 systemd-journal\n  812 ?        00:00:01 sshd\n 1420 pts/0    00:00:00 bash\n 1489 pts/0    00:00:00 ps\n"
	case "cat":
		if len(parts) < 2 {
			return "cat: missing file operand\n"
		}
		target := fs.resolvePath(parts[1])
		if content, ok := fs.files[target]; ok {
			return content
		}
		return fmt.Sprintf("cat: %s: No such file or directory\n", parts[1])
	case "head":
		if len(parts) < 2 {
			return "head: missing file operand\n"
		}
		target := fs.resolvePath(parts[len(parts)-1])
		if content, ok := fs.files[target]; ok {
			lines := strings.Split(content, "\n")
			limit := 10
			if len(lines) < limit {
				limit = len(lines)
			}
			return strings.Join(lines[:limit], "\n") + "\n"
		}
		return fmt.Sprintf("head: cannot open '%s' for reading: No such file or directory\n", parts[len(parts)-1])
	case "find":
		var matches []string
		for p := range fs.files {
			matches = append(matches, p)
		}
		return strings.Join(matches, "\n") + "\n"
	case "env":
		var b strings.Builder
		for k, v := range fs.env {
			b.WriteString(fmt.Sprintf("%s=%s\n", k, v))
		}
		return b.String()
	case "echo":
		if len(parts) > 1 && strings.HasPrefix(parts[1], "$") {
			varName := strings.TrimPrefix(parts[1], "$")
			if v, ok := fs.env[varName]; ok {
				return v + "\n"
			}
			return "\n"
		}
		if len(parts) > 1 {
			return strings.Join(parts[1:], " ") + "\n"
		}
		return "\n"
	case "ls":
		isLong := false
		for _, arg := range parts[1:] {
			if strings.Contains(arg, "l") {
				isLong = true
			}
		}
		if isLong {
			if fs.cwd == "/root" {
				return "total 24\ndrwx------ 3 root root 4096 Sep  5 12:00 .\ndrwxr-xr-x 18 root root 4096 Aug 15 08:30 ..\n-rw------- 1 root root  214 Sep  5 12:01 .bash_history\n-rw-r--r-- 1 root root  570 Aug 15 08:30 .bashrc\n-rw------- 1 root root  280 Sep  5 12:00 .env\n-rw-r--r-- 1 root root  148 Aug 15 08:30 .profile\n"
			}
			return "total 64\ndrwxr-xr-x  18 root root  4096 Aug 15 08:30 .\ndrwxr-xr-x  18 root root  4096 Aug 15 08:30 ..\nlrwxrwxrwx   1 root root     7 Aug 15 08:30 bin -> usr/bin\ndrwxr-xr-x   3 root root  4096 Aug 15 08:30 boot\ndrwxr-xr-x  14 root root  3140 Aug 15 08:30 dev\ndrwxr-xr-x  45 root root  4096 Sep  5 12:00 etc\ndrwxr-xr-x   3 root root  4096 Aug 15 08:30 home\ndrwx------   3 root root  4096 Sep  5 12:00 root\ndrwxr-xr-x  11 root root  4096 Aug 15 08:30 var\n"
		}
		if fs.cwd == "/root" {
			return ".bash_history  .bashrc  .env  .profile\n"
		}
		return "bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\n"
	case "curl", "wget":
		return fmt.Sprintf("%s: connecting... connection timed out.\n", binary)
	case "history":
		var b strings.Builder
		for i, h := range fs.history {
			b.WriteString(fmt.Sprintf("  %4d  %s\n", i+1, h))
		}
		return b.String()
	case "exit", "logout":
		return "logout\n"
	default:
		return fmt.Sprintf("bash: %s: command not found\n", binary)
	}
}

func (fs *VirtualFS) resolvePath(p string) string {
	if !strings.HasPrefix(p, "/") {
		if fs.cwd == "/" {
			p = "/" + p
		} else {
			p = fs.cwd + "/" + p
		}
	}
	p = strings.ReplaceAll(p, "//", "/")
	return p
}
