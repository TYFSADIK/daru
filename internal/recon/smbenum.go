package recon

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Native SMB/NetBIOS enumeration, built on tools that ship with Samba
// (smbclient, rpcclient, nmblookup, net). It gives enum4linux-style results
// , shares, NetBIOS names, server info, domain users and groups, without
// requiring enum4linux itself to be installed. Every probe uses a null
// session (anonymous); nothing here brute-forces credentials.
func init() {
	register(&Connector{
		Name: "smb-enum", Binary: "smbclient", Category: CatEnum, TargetKind: TgtHost,
		Desc:     "SMB/NetBIOS enumeration (shares, NetBIOS names, server info, users, groups) via Samba tools.",
		Profiles: []Profile{{"anon", "Anonymous (null-session) enumeration"}},
		native:   smbEnum,
	})
}

// enum4linuxRun returns a native collector that runs the named enum4linux
// binary when it is installed (parsing its text output), and otherwise falls
// back to Daru's native SMB enumeration so the connector always works.
func enum4linuxRun(binName, allFlag string) func(context.Context, Request) ([]Finding, error) {
	return func(ctx context.Context, r Request) ([]Finding, error) {
		if strings.TrimSpace(r.Target) == "" {
			return nil, fmt.Errorf("a target host is required")
		}
		if bin := resolveBinary(binName); bin != "" {
			out, _ := runTool(ctx, bin, 4*time.Minute, allFlag, r.Target)
			if f := parseEnum4linux(out, r.Target); len(f) > 0 {
				return f, nil
			}
		}
		// Binary absent or produced nothing usable: native fallback.
		return smbEnum(ctx, r)
	}
}

// parseEnum4linux extracts the useful lines from enum4linux / enum4linux-ng
// text output: shares, users, groups, OS, domain info, SMB dialects, signing
// posture and anonymous-session results. It understands both the classic
// enum4linux format and the richer key/value output of enum4linux-ng.
func parseEnum4linux(out, target string) []Finding {
	var findings []Finding
	add := func(sev, title string) {
		if title = strings.TrimSpace(title); title != "" {
			findings = append(findings, Finding{Title: title, Severity: sev, Target: target, Service: "smb"})
		}
	}
	seen := map[string]bool{}
	addUniq := func(sev, title string) {
		if seen[title] {
			return
		}
		seen[title] = true
		add(sev, title)
	}

	for _, line := range strings.Split(out, "\n") {
		raw := stripANSI(line)
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		low := strings.ToLower(t)
		// Strip enum4linux-ng status markers ([+]/[*]/[-]/[!]) for titles.
		msg := t
		for _, p := range []string{"[+] ", "[*] ", "[-] ", "[!] "} {
			msg = strings.TrimPrefix(msg, p)
		}
		kv := func(prefix string) (string, bool) {
			if strings.HasPrefix(low, strings.ToLower(prefix)) {
				return strings.TrimSpace(t[len(prefix):]), true
			}
			return "", false
		}

		switch {
		// ---- enum4linux-ng security-relevant posture ----
		case strings.HasPrefix(low, "smb 1.0:") && strings.Contains(low, "true"):
			addUniq("medium", "SMBv1 (SMB 1.0) is enabled, legacy, EternalBlue-class exposure")
		case strings.HasPrefix(low, "smb1 only:") && strings.Contains(low, "true"):
			addUniq("medium", "Host speaks SMB1 only, deprecated and insecure")
		case strings.HasPrefix(low, "smb signing required:"):
			if strings.Contains(low, "false") {
				addUniq("medium", "SMB signing is NOT required, susceptible to relay/MITM")
			} else {
				addUniq("info", "SMB signing required: true")
			}
		case strings.HasPrefix(low, "preferred dialect:"):
			if v, ok := kv("Preferred dialect:"); ok {
				addUniq("info", "SMB preferred dialect: "+v)
			}
		// Anonymous/guest access actually succeeding is a real finding.
		case strings.Contains(low, "server allows session using username"),
			strings.Contains(low, "null session") && strings.Contains(low, "succ"),
			strings.Contains(low, "allows sessions using a null"):
			addUniq("high", "Anonymous (null) SMB session permitted: "+msg)
		case strings.Contains(low, "guest") && strings.Contains(low, "succ") && strings.Contains(low, "session"):
			addUniq("high", "Guest SMB session permitted: "+msg)

		// ---- identity / fingerprint key:values ----
		case strings.HasPrefix(low, "netbios computer name:"):
			if v, ok := kv("NetBIOS computer name:"); ok {
				addUniq("info", "NetBIOS computer name: "+v)
			}
		case strings.HasPrefix(low, "dns domain:"):
			if v, ok := kv("DNS domain:"); ok {
				addUniq("info", "DNS domain: "+v)
			}
		case strings.HasPrefix(low, "fqdn:"):
			if v, ok := kv("FQDN:"); ok {
				addUniq("info", "FQDN: "+v)
			}
		case strings.Contains(low, "got domain/workgroup name:"):
			addUniq("info", msg)
		case strings.HasPrefix(low, "os:") && len(t) < 160:
			if v, ok := kv("OS:"); ok {
				addUniq("info", "OS: "+v)
			}
		case strings.HasPrefix(low, "os build:"):
			if v, ok := kv("OS build:"); ok {
				addUniq("info", "OS build: "+strings.Trim(v, "'"))
			}
		case strings.Contains(low, "mac address ="):
			if i := strings.Index(low, "mac address ="); i >= 0 {
				addUniq("info", "MAC Address = "+strings.TrimSpace(t[i+len("mac address ="):]))
			}
		case strings.HasPrefix(t, "- ") && strings.Contains(t, "<") && strings.Contains(low, "service"):
			addUniq("info", "NetBIOS: "+strings.TrimPrefix(t, "- "))

		// ---- classic enum4linux format ----
		case strings.Contains(low, "mapping:") && strings.Contains(low, "ok"):
			add("low", msg)
		case strings.HasPrefix(low, "user:") || strings.Contains(t, "rid:[0x") && strings.Contains(low, "user"):
			add("low", "User: "+msg)
		case strings.Contains(low, "group:") && strings.Contains(t, "rid:[0x"):
			add("info", "Group: "+msg)
		case strings.HasPrefix(low, "mapping to share") || strings.Contains(low, "disk|") || strings.Contains(low, "share is readable"):
			add("low", msg)
		case strings.HasPrefix(low, "os=") || strings.HasPrefix(low, "domain=") || strings.HasPrefix(low, "server="):
			add("info", msg)
		}
	}
	return findings
}

func smbEnum(ctx context.Context, r Request) ([]Finding, error) {
	target := strings.TrimSpace(r.Target)
	if target == "" {
		return nil, fmt.Errorf("a target host is required")
	}
	// Optional non-standard SMB port (default 445).
	var portArgs []string
	if r.Ports != "" {
		if !validPorts(r.Ports) {
			return nil, fmt.Errorf("invalid port")
		}
		portArgs = []string{"-p", r.Ports}
	}
	var findings []Finding
	ran := false

	// 1. Shares via smbclient -L.
	if bin := resolveBinary("smbclient"); bin != "" {
		ran = true
		args := append([]string{"-L", "//" + target, "-N"}, portArgs...)
		if out, _ := runTool(ctx, bin, 25*time.Second, args...); out != "" {
			findings = append(findings, parseSmbShares(out, target)...)
		}
	}

	// 2. NetBIOS name table via nmblookup -A (standard port only).
	if r.Ports == "" {
		if bin := resolveBinary("nmblookup"); bin != "" {
			ran = true
			if out, _ := runTool(ctx, bin, 15*time.Second, "-A", target); out != "" {
				findings = append(findings, parseNmblookup(out, target)...)
			}
		}
	}

	// 3. Server/domain info, password policy, users, groups, and the domain SID
	//    via an rpcclient null session. getdompwinfo exposes the account
	//    lockout/complexity policy; lsaquery returns the domain SID; the enum*
	//    commands list principals. Hosts that refuse anonymous RPC (like a
	//    SOHO router) simply return nothing for these, which is fine.
	if bin := resolveBinary("rpcclient"); bin != "" {
		ran = true
		cmd := "srvinfo;lsaquery;querydominfo;getdompwinfo;enumdomusers;enumdomgroups;enumalsgroups builtin"
		args := append([]string{"-U", "", "-N"}, portArgs...)
		args = append(args, target, "-c", cmd)
		if out, _ := runTool(ctx, bin, 40*time.Second, args...); out != "" {
			findings = append(findings, parseRpcclient(out, target)...)
		}
	}

	if !ran {
		return nil, fmt.Errorf("SMB enumeration needs Samba client tools (smbclient, rpcclient, nmblookup)")
	}
	if len(findings) == 0 {
		findings = append(findings, Finding{
			Title: "SMB reachable but anonymous enumeration returned nothing", Severity: "info",
			Target: target, Service: "smb",
		})
	}
	return findings, nil
}

// MaxToolOutputBytes caps output from a native helper tool.
const MaxToolOutputBytes = 1 << 20

// runTool runs a command with a timeout and returns combined output, capped
// at MaxToolOutputBytes so a chatty tool cannot exhaust memory.
func runTool(ctx context.Context, bin string, timeout time.Duration, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...) // #nosec G204 -- recon tools run as an argv list (no shell) from a vetted binary path
	var buf bytes.Buffer
	cmd.Stdout = capWriter(&buf, MaxToolOutputBytes)
	cmd.Stderr = capWriter(&buf, MaxToolOutputBytes)
	err := cmd.Run()
	return buf.String(), err
}

func parseSmbShares(out, target string) []Finding {
	var findings []Finding
	inShares := false
	for _, raw := range strings.Split(out, "\n") {
		t := strings.TrimSpace(stripANSI(raw))
		if strings.HasPrefix(t, "Sharename") {
			inShares = true
			continue
		}
		if strings.HasPrefix(t, "---") {
			continue
		}
		if inShares {
			if t == "" {
				inShares = false
				continue
			}
			f := strings.Fields(t)
			if len(f) < 2 {
				continue
			}
			share, typ := f[0], f[1]
			// A real share row's type is one of these; this skips trailing
			// status lines such as "SMB1 disabled -- no workgroup available".
			switch typ {
			case "Disk", "IPC", "Printer":
			default:
				inShares = false
				continue
			}
			comment := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(t, share), typ))
			sev := "info"
			if typ == "Disk" {
				sev = "low" // a readable disk share is worth noting
			}
			findings = append(findings, Finding{
				Title: "Share: " + share + " (" + typ + ")", Severity: sev, Target: target, Service: "smb",
				Detail: comment, Fields: map[string]string{"share": share, "type": typ, "comment": comment},
			})
		}
	}
	return findings
}

var nmblookupRe = regexp.MustCompile(`^\s*(\S+)\s+<([0-9a-fA-F]{2})>\s+-\s*(.*)$`)

// nbtHostname resolves a host's NetBIOS computer name via nmblookup -A. It
// returns the unique workstation/server name (the <00>/<20> entry that is not a
// <GROUP>), which is the Windows hostname that reverse DNS usually misses.
func nbtHostname(ctx context.Context, ip string) string {
	bin := resolveBinary("nmblookup")
	if bin == "" {
		return ""
	}
	out, _ := runTool(ctx, bin, 12*time.Second, "-A", ip)
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(strings.ToUpper(line), "<GROUP>") {
			continue // workgroup/domain name, not the host
		}
		m := nmblookupRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		code := strings.ToLower(m[2])
		if code == "00" || code == "20" {
			if name := strings.TrimSpace(m[1]); name != "" {
				return name
			}
		}
	}
	return ""
}

func parseNmblookup(out, target string) []Finding {
	var findings []Finding
	for _, line := range strings.Split(out, "\n") {
		m := nmblookupRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name, code := strings.TrimSpace(m[1]), m[2]
		findings = append(findings, Finding{
			Title: "NetBIOS: " + name + " <" + code + ">", Severity: "info", Target: target, Service: "netbios",
			Detail: strings.TrimSpace(m[3]),
			Fields: map[string]string{"_kind": "host", "ip": target, "hostname": name, "netbios_code": code},
		})
	}
	return findings
}

func parseRpcclient(out, target string) []Finding {
	var findings []Finding
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.Contains(t, "NT_STATUS") && strings.Contains(t, "DENIED") {
			continue
		}
		switch {
		case strings.HasPrefix(t, "user:["):
			name := between(t, "user:[", "]")
			findings = append(findings, Finding{Title: "User: " + name, Severity: "low", Target: target, Service: "smb",
				Fields: map[string]string{"user": name}})
		case strings.HasPrefix(t, "group:["):
			name := between(t, "group:[", "]")
			findings = append(findings, Finding{Title: "Group: " + name, Severity: "info", Target: target, Service: "smb",
				Fields: map[string]string{"group": name}})
		case strings.HasPrefix(t, "Domain:") || strings.HasPrefix(t, "Server:") || strings.HasPrefix(t, "OS version:") ||
			strings.HasPrefix(t, "platform_id") || strings.HasPrefix(t, "Domain Controllers"):
			findings = append(findings, Finding{Title: t, Severity: "info", Target: target, Service: "smb"})
		case strings.HasPrefix(t, "Domain Sid:") || strings.HasPrefix(t, "Domain Name:"):
			findings = append(findings, Finding{Title: t, Severity: "info", Target: target, Service: "smb"})
		case strings.Contains(t, "min_password_length:") || strings.Contains(t, "password_properties:") ||
			strings.HasPrefix(t, "min_pass") || strings.HasPrefix(t, "password_"):
			// Weak password policy is a real finding worth flagging.
			sev := "info"
			if strings.Contains(t, "min_password_length: 0") {
				sev = "medium"
			}
			findings = append(findings, Finding{Title: "Password policy: " + t, Severity: sev, Target: target, Service: "smb",
				Fields: map[string]string{"policy": t}})
		}
	}
	return findings
}

func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	i += len(start)
	j := strings.Index(s[i:], end)
	if j < 0 {
		return ""
	}
	return s[i : i+j]
}
