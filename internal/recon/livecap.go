package recon

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

func newToken() string {
	var b [12]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Packet is one captured frame, decoded to the fields a dashboard needs. It is
// deliberately Wireshark-like: layer protocol, addresses, ports, length, and a
// human-readable info column.
type Packet struct {
	Seq      int64  `json:"seq"`
	TimeMs   int64  `json:"time_ms"`
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  string `json:"src_port"`
	DstPort  string `json:"dst_port"`
	Protocol string `json:"protocol"`
	Length   int    `json:"length"`
	SrcMAC   string `json:"src_mac"`
	DstMAC   string `json:"dst_mac"`
	Info     string `json:"info"`
	DNSQuery string `json:"dns_query,omitempty"`
	HTTPHost string `json:"http_host,omitempty"`
	SNI      string `json:"sni,omitempty"`
}

// CaptureSession is a running live capture. Packets are delivered on C until
// the session ends (duration elapses, Stop is called, or an error occurs).
type CaptureSession struct {
	ID        string
	PcapPath  string // raw capture file, or "" when this engine cannot save one
	Iface     string
	Filter    string
	engine    string
	Started   time.Time
	C         chan Packet
	cancel    context.CancelFunc
	mu        sync.Mutex
	done      bool
	err       string
	seq       int64
	totalPkts int64
}

// tshark field order for -T fields; keep in sync with parseLive below.
var liveFields = []string{
	"frame.time_epoch", "frame.len", "eth.src", "eth.dst",
	"ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
	"_ws.col.Protocol", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
	"dns.qry.name", "http.host", "tls.handshake.extensions_server_name", "_ws.col.Info",
}

// CaptureFilter is a safe, allowlisted capture configuration from the client.
type CaptureFilter struct {
	Iface       string
	BPF         string // optional libpcap filter, validated
	DurationSec int
	// Admin marks a capture requested by an admin: loopback and long
	// captures are allowed. Power users are capped at 300s and may not
	// capture on loopback.
	Admin bool
	// PcapPath, when set, also saves the raw capture there for download.
	// The tcpdump-text engine cannot, so check CaptureSession.PcapPath.
	PcapPath string
}

// CapturePcapMaxBytes caps a saved capture file. tshark stops the capture
// at this size; the tcpdump pipe stops writing the file but keeps streaming.
const CapturePcapMaxBytes = 200 << 20

// cappedFile writes to f until max bytes, then discards the rest. A short
// write never fails the stream it is teed from.
type cappedFile struct {
	f       *os.File
	max     int64
	written int64
}

func (c *cappedFile) Write(p []byte) (int, error) {
	if c.written < c.max {
		n := int64(len(p))
		if c.written+n > c.max {
			n = c.max - c.written
		}
		w, err := c.f.Write(p[:n])
		c.written += int64(w)
		if err != nil {
			c.written = c.max // stop trying after a disk error
		}
	}
	return len(p), nil
}

// MaxPowerCaptureSec caps a non-admin live capture.
const MaxPowerCaptureSec = 300

// MaxAdminCaptureSec caps an admin live capture.
const MaxAdminCaptureSec = 3600

// CapturePacketCap is the packet cap per second of capture (dur * 1000).
const CapturePacketCap = 1000

// allowedCaptureIfaces returns the interface allowlist from
// DARU_CAPTURE_IFACES (comma separated). Empty means all interfaces
// except loopback are allowed.
func allowedCaptureIfaces() []string {
	v := strings.TrimSpace(os.Getenv("DARU_CAPTURE_IFACES"))
	if v == "" {
		return nil
	}
	var out []string
	for _, f := range strings.Split(v, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// ValidateCaptureFilter checks interface scope and duration for a capture.
func ValidateCaptureFilter(f CaptureFilter) error {
	if !ifaceName(f.Iface) {
		return fmt.Errorf("invalid interface name")
	}
	if f.Iface == "lo" && !f.Admin {
		return fmt.Errorf("loopback capture requires admin")
	}
	if allow := allowedCaptureIfaces(); len(allow) > 0 {
		ok := false
		for _, a := range allow {
			if a == f.Iface {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("interface %q is not on the capture allowlist (DARU_CAPTURE_IFACES)", f.Iface)
		}
	}
	return nil
}

// clampCaptureDuration bounds a capture duration by role.
func clampCaptureDuration(dur int, admin bool) int {
	max := MaxPowerCaptureSec
	if admin {
		max = MaxAdminCaptureSec
	}
	if dur <= 0 || dur > max {
		return max
	}
	return dur
}

// Engine names for the capture backend.
const (
	engineTshark     = "tshark"
	engineTcpdump    = "tcpdump"
	engineTsharkPipe = "tshark-pipe" // tcpdump captures, tshark decodes (rich, no group)
)

// Engine returns which capture backend will be used, for display.
func (s *CaptureSession) Engine() string { return s.engine }

// chooseCaptureEngine prefers tshark (it decodes DNS/TLS SNI/HTTP host) but
// only when dumpcap is actually runnable by this process; otherwise it falls
// back to tcpdump, which commonly has CAP_NET_RAW and needs no wireshark-group
// membership. Returns the engine name and its binary path.
func chooseCaptureEngine() (string, string) {
	tshark := resolveBinary("tshark")
	tcpdump := resolveBinary("tcpdump")
	// Best: tshark doing its own live capture (needs runnable dumpcap).
	if tshark != "" && dumpcapRunnable() {
		return engineTshark, tshark
	}
	// Next best: tcpdump captures (it has CAP_NET_RAW) and tshark decodes the
	// stream, rich DNS/TLS-SNI/HTTP without wireshark-group membership.
	if tshark != "" && tcpdump != "" {
		return engineTsharkPipe, tshark
	}
	// Plain tcpdump text parsing.
	if tcpdump != "" {
		return engineTcpdump, tcpdump
	}
	// tshark only; try it so the user gets the real permission error.
	if tshark != "" {
		return engineTshark, tshark
	}
	return "", ""
}

// dumpcapRunnable reports whether this process can execute dumpcap (tshark's
// capture child). It runs `dumpcap -D` briefly; a permission failure here is
// exactly what makes a tshark capture silently return nothing.
func dumpcapRunnable() bool {
	bin := firstExisting("dumpcap", "/usr/bin/dumpcap", "/usr/sbin/dumpcap", "/opt/homebrew/bin/dumpcap")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-D").CombinedOutput() // #nosec G204 -- recon tools run as an argv list (no shell) from a vetted binary path
	if err != nil {
		return false
	}
	return !strings.Contains(strings.ToLower(string(out)), "permission denied")
}

// StartCapture launches a packet capture on an interface and streams decoded
// packets. It validates all inputs and auto-selects tshark or tcpdump.
func StartCapture(parent context.Context, f CaptureFilter) (*CaptureSession, error) {
	if err := ValidateCaptureFilter(f); err != nil {
		return nil, err
	}
	engine, bin := chooseCaptureEngine()
	if bin == "" {
		return nil, fmt.Errorf("no capture tool found; install tshark (wireshark) or tcpdump")
	}
	if f.BPF != "" && !validBPF(f.BPF) {
		return nil, fmt.Errorf("capture filter contains unsupported characters")
	}
	dur := clampCaptureDuration(f.DurationSec, f.Admin)
	// Bound the whole capture by its duration (plus grace for tshark, which
	// also self-terminates via -a duration).
	ctx, cancel := context.WithTimeout(parent, time.Duration(dur+5)*time.Second)

	var stdout io.Reader
	var waitFn func()
	pcapPath := ""
	closePcap := func() {}
	var errText func() string
	parseFn := parseLive

	if engine == engineTsharkPipe {
		// tcpdump captures to a pcap stream on stdout (it has CAP_NET_RAW),
		// piped into tshark reading that stream (-r -), which needs no capture
		// privilege. Result: live capture WITH tshark's rich DNS/TLS-SNI/HTTP
		// decode, without wireshark-group membership.
		tcpdumpBin := resolveBinary("tcpdump")
		capArgs := []string{"-i", f.Iface, "-w", "-", "-U", "-s", "262144", "-c", strconv.Itoa(dur * CapturePacketCap)}
		if f.BPF != "" {
			// BPF is one argv element, never split: a split filter can be
			// reinterpreted by getopt as tcpdump options (-w, -r, ...).
			capArgs = append(capArgs, f.BPF)
		}
		readArgs := []string{"-r", "-", "-l", "-n", "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"}
		for _, fld := range liveFields {
			readArgs = append(readArgs, "-e", fld)
		}
		c1 := exec.CommandContext(ctx, tcpdumpBin, capArgs...) // #nosec G204 -- recon tools run as an argv list (no shell) from a vetted binary path
		c2 := exec.CommandContext(ctx, bin, readArgs...)       // #nosec G204 -- recon tools run as an argv list (no shell) from a vetted binary path
		pr, pw := io.Pipe()
		c1.Stdout = pw
		if f.PcapPath != "" {
			// Tee the raw pcap stream into the download file.
			pf, err := os.OpenFile(f.PcapPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- the path is generated by the server, never from a request
			if err != nil {
				cancel()
				return nil, fmt.Errorf("could not create capture file: %w", err)
			}
			c1.Stdout = io.MultiWriter(pw, &cappedFile{f: pf, max: CapturePcapMaxBytes})
			pcapPath = f.PcapPath
			closePcap = func() { _ = pf.Close() }
		}
		c2.Stdin = pr
		eb := newErrBuf()
		c1.Stderr = eb
		so, err := c2.StdoutPipe()
		if err != nil {
			cancel()
			return nil, err
		}
		stdout = so
		if err := c2.Start(); err != nil {
			cancel()
			return nil, err
		}
		if err := c1.Start(); err != nil {
			cancel()
			_ = c2.Process.Kill()
			return nil, fmt.Errorf("could not start capture: %w", err)
		}
		waitFn = func() { _ = c1.Wait(); _ = pw.Close(); _ = c2.Wait(); closePcap() } // failures surface via errText
		errText = eb.String
	} else {
		var args []string
		if engine == engineTshark {
			args = []string{"-i", f.Iface, "-l", "-n", "-a", "duration:" + strconv.Itoa(dur),
				"-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"}
			for _, fld := range liveFields {
				args = append(args, "-e", fld)
			}
			if f.BPF != "" {
				args = append(args, "-f", f.BPF)
			}
			if f.PcapPath != "" {
				// -w saves the raw capture (mode 0600); -P keeps printing
				// the decoded fields; filesize stops at the cap (in KB).
				args = append(args, "-w", f.PcapPath, "-P", "-a", "filesize:"+strconv.Itoa(CapturePcapMaxBytes>>10))
				pcapPath = f.PcapPath
			}
		} else {
			parseFn = parseTcpdump
			args = []string{"-i", f.Iface, "-l", "-nn", "-tt", "-e", "-Q", "inout", "-c", strconv.Itoa(dur * CapturePacketCap)}
			if f.BPF != "" {
				args = append(args, f.BPF)
			}
		}
		cmd := exec.CommandContext(ctx, bin, args...) // #nosec G204 -- recon tools run as an argv list (no shell) from a vetted binary path
		so, err := cmd.StdoutPipe()
		if err != nil {
			cancel()
			return nil, err
		}
		stdout = so
		eb := newErrBuf()
		cmd.Stderr = eb
		if err := cmd.Start(); err != nil {
			cancel()
			return nil, fmt.Errorf("could not start capture: %w (needs capture permission; run scripts/grant-capabilities.sh)", err)
		}
		waitFn = func() { _ = cmd.Wait() } // failures surface via errText
		errText = eb.String
	}

	s := &CaptureSession{
		ID: newToken(), Iface: f.Iface, Filter: f.BPF, engine: engine, Started: time.Now(), PcapPath: pcapPath,
		C: make(chan Packet, 512), cancel: cancel,
	}
	go func() {
		defer close(s.C)
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			p, ok := parseFn(sc.Text())
			if !ok {
				continue
			}
			s.mu.Lock()
			s.seq++
			s.totalPkts++
			p.Seq = s.seq
			s.mu.Unlock()
			select {
			case s.C <- p:
			case <-ctx.Done():
				waitFn()
				return
			default:
			}
		}
		waitFn()
		s.mu.Lock()
		s.done = true
		if s.totalPkts == 0 {
			s.err = friendlyCaptureErr(errText())
		}
		s.mu.Unlock()
	}()
	return s, nil
}

// errBuf is a small thread-safe, size-capped writer for a child's stderr.
type errBuf struct {
	mu  sync.Mutex
	b   strings.Builder
	cap int
}

func newErrBuf() *errBuf { return &errBuf{cap: 4000} }

func (e *errBuf) Write(p []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.b.Len() < e.cap {
		e.b.Write(p)
	}
	return len(p), nil
}

func (e *errBuf) String() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.b.String()
}

// friendlyCaptureErr turns tshark/dumpcap stderr into an actionable message.
func friendlyCaptureErr(raw string) string {
	low := strings.ToLower(raw)
	switch {
	case low == "":
		return ""
	case strings.Contains(low, "permission denied") || strings.Contains(low, "couldn't run dumpcap"):
		return "capture permission denied: run `sh scripts/grant-capabilities.sh` and make sure your user is in the 'wireshark' group (then log out and back in)"
	case strings.Contains(low, "no such") || strings.Contains(low, "doesn't exist"):
		return "that interface was not found"
	default:
		return strings.TrimSpace(strings.SplitN(raw, "\n", 2)[0])
	}
}

// Err returns the capture error, if any (available after the stream ends).
func (s *CaptureSession) Err() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Stop ends the capture.
func (s *CaptureSession) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

// Total returns how many packets have been seen.
func (s *CaptureSession) Total() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.totalPkts
}

func parseLive(line string) (Packet, bool) {
	cols := strings.Split(line, "\t")
	if len(cols) < len(liveFields) {
		// pad so index access is safe
		pad := make([]string, len(liveFields))
		copy(pad, cols)
		cols = pad
	}
	get := func(i int) string { return strings.TrimSpace(cols[i]) }
	epoch := get(0)
	if epoch == "" {
		return Packet{}, false
	}
	tms := int64(0)
	if f, err := strconv.ParseFloat(epoch, 64); err == nil {
		tms = int64(f * 1000)
	}
	p := Packet{
		TimeMs:   tms,
		Length:   atoi(get(1)),
		SrcMAC:   get(2),
		DstMAC:   get(3),
		Protocol: get(8),
		DNSQuery: get(13),
		HTTPHost: get(14),
		SNI:      get(15),
		Info:     get(16),
	}
	p.SrcIP = firstNonEmptyStr(get(4), get(6))
	p.DstIP = firstNonEmptyStr(get(5), get(7))
	p.SrcPort = firstNonEmptyStr(get(9), get(11))
	p.DstPort = firstNonEmptyStr(get(10), get(12))
	return p, true
}

// tcpdumpLineRe matches the leading part of a `tcpdump -nn -tt -e` line:
//
//	<epoch> <srcmac> > <dstmac>, ethertype <T> (0x..), length <N>: <rest>
var tcpdumpLineRe = regexp.MustCompile(`^(\d+\.\d+)\s+([0-9a-fA-F:]{17}) > ([0-9a-fA-F:]{17}),\s+ethertype\s+(\S+)\s+\([^)]*\),\s+length\s+(\d+):\s*(.*)$`)

// parseTcpdump decodes one tcpdump text line into a Packet. It is best-effort:
// addresses/ports/protocol are extracted when present, and the remaining text
// is always kept as the Info column.
func parseTcpdump(line string) (Packet, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Packet{}, false
	}
	m := tcpdumpLineRe.FindStringSubmatch(line)
	if m == nil {
		// Lines without the ethernet header (or control lines) are skipped.
		return Packet{}, false
	}
	ethertype := m[4]
	p := Packet{SrcMAC: strings.ToLower(m[2]), DstMAC: strings.ToLower(m[3]), Length: atoi(m[5])}
	if f, err := strconv.ParseFloat(m[1], 64); err == nil {
		p.TimeMs = int64(f * 1000)
	}
	rest := m[6]
	p.Info = rest

	// ARP has no L3 addresses in the usual form; label it directly.
	if strings.EqualFold(ethertype, "ARP") || strings.HasPrefix(rest, "Request who-has") || strings.HasPrefix(rest, "Reply ") {
		p.Protocol = "ARP"
		return p, true
	}

	// rest looks like "SRC > DST: PROTO, length N" or "SRC > DST: Flags [S], ..."
	// Split endpoints on the first " > ".
	if gt := strings.Index(rest, " > "); gt >= 0 {
		src := strings.TrimSpace(rest[:gt])
		after := rest[gt+3:]
		dst := after
		proto := ""
		if colon := strings.Index(after, ":"); colon >= 0 {
			dst = strings.TrimSpace(after[:colon])
			tail := strings.TrimSpace(after[colon+1:])
			proto = firstWord(tail)
		}
		p.SrcIP, p.SrcPort = splitHostPort(src)
		p.DstIP, p.DstPort = splitHostPort(dst)
		p.Protocol = normalizeProto(proto, p.DstPort, p.SrcPort)
	} else {
		p.Protocol = sanitizeProto(firstWord(rest))
	}
	return p, true
}

// splitHostPort splits tcpdump's "host.port" notation (works for IPv4 and the
// IPv6 "addr.port" form) into address and port. If the trailing dotted segment
// is not numeric, the whole string is treated as the host.
func splitHostPort(s string) (string, string) {
	s = strings.TrimSpace(s)
	i := strings.LastIndex(s, ".")
	if i < 0 || i == len(s)-1 {
		return s, ""
	}
	port := s[i+1:]
	for _, r := range port {
		if r < '0' || r > '9' {
			return s, ""
		}
	}
	return s[:i], port
}

func firstWord(s string) string {
	s = strings.TrimSpace(s)
	for i, r := range s {
		if r == ' ' || r == ',' {
			return s[:i]
		}
	}
	return s
}

// normalizeProto upgrades tcpdump's coarse label using well-known ports so the
// dashboard shows HTTPS/DNS/etc. rather than bare TCP/UDP, and cleans junk
// tokens (mDNS transaction ids, stray punctuation) into a sensible label.
func normalizeProto(proto, dstPort, srcPort string) string {
	byPort := func(pt string) string {
		switch pt {
		case "443", "8443":
			return "TLS"
		case "80", "8080":
			return "HTTP"
		case "53":
			return "DNS"
		case "5353":
			return "MDNS"
		case "5355":
			return "LLMNR"
		case "137", "138":
			return "NETBIOS"
		case "1900":
			return "SSDP"
		case "22":
			return "SSH"
		case "123":
			return "NTP"
		case "67", "68":
			return "DHCP"
		case "161", "162":
			return "SNMP"
		}
		return ""
	}
	if n := byPort(dstPort); n != "" {
		return n
	}
	if n := byPort(srcPort); n != "" {
		return n
	}
	up := sanitizeProto(proto)
	if up == "" {
		if dstPort != "" || srcPort != "" {
			return "UDP" // has L4 ports but unknown app → generic datagram
		}
		return "IP"
	}
	if up == "FLAGS" { // "Flags [S]" form is a TCP segment
		return "TCP"
	}
	return up
}

// sanitizeProto keeps only a clean alphabetic protocol token, discarding
// numeric ids and punctuation that tcpdump sometimes emits (e.g. mDNS "0*-").
func sanitizeProto(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	// Keep leading letters only.
	end := 0
	for end < len(s) {
		c := s[end]
		if c >= 'A' && c <= 'Z' {
			end++
		} else {
			break
		}
	}
	if end < 2 {
		return ""
	}
	return s[:end]
}

// bpfOptionTokens are tcpdump options a filter must never be able to
// smuggle in as a token.
var bpfOptionTokens = map[string]bool{
	"-w": true, "-r": true, "-F": true, "-z": true,
	"-C": true, "-G": true, "-W": true,
}

// validBPF allows a conservative subset of libpcap filter syntax. Any token
// starting with '-' is rejected, so a filter can never be reinterpreted as
// a tcpdump option by getopt permutation.
func validBPF(s string) bool {
	if len(s) > 256 {
		return false
	}
	for _, tok := range strings.Fields(s) {
		if strings.HasPrefix(tok, "-") {
			return false
		}
		if bpfOptionTokens[tok] {
			return false
		}
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == ' ' || r == '.' || r == ':' || r == '/' || r == '-' || r == '_':
		case r == '(' || r == ')' || r == '!' || r == '=':
		default:
			return false
		}
	}
	return true
}
