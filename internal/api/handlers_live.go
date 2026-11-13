package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/TYFSADIK/daru/internal/auth"
	"github.com/TYFSADIK/daru/internal/recon"
	"github.com/TYFSADIK/daru/internal/store"
)

// handleLiveInterfaces returns a live snapshot of every local interface,
// including WiFi link stats and byte/packet counters the UI diffs for live
// throughput.
func (s *Server) handleLiveInterfaces(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"interfaces": recon.Interfaces(r.Context())})
}

// handleLiveCapture streams decoded packets over Server-Sent Events. The
// browser opens it with EventSource (cookie-authenticated, same origin).
// Query params: iface (required), duration (seconds), filter (BPF).
func (s *Server) handleLiveCapture(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	// Bound concurrent captures so a few open tabs cannot exhaust the host.
	select {
	case s.capSem <- struct{}{}:
		defer func() { <-s.capSem }()
	default:
		writeError(w, http.StatusTooManyRequests, "too many live captures in progress")
		return
	}

	q := r.URL.Query()
	dur, _ := strconv.Atoi(q.Get("duration"))
	admin := false
	if sess := sessionFrom(r.Context()); sess != nil && sess.Role == auth.RoleAdmin {
		admin = true
	}
	f := recon.CaptureFilter{Iface: q.Get("iface"), BPF: q.Get("filter"), DurationSec: dur, Admin: admin}
	sess, err := recon.StartCapture(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer sess.Stop()

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "event: open\ndata: {\"iface\":%q,\"id\":%q,\"engine\":%q}\n\n", sess.Iface, sess.ID, sess.Engine())
	flusher.Flush()

	stats := time.NewTicker(time.Second)
	defer stats.Stop()
	user := sessionFrom(r.Context()).Username
	s.Log.Info("live capture started", "iface", sess.Iface, "user", user)

	// Optional: persist captured packets as searchable events (index
	// "network", sourcetype "packet"), bounded so a long capture can't flood
	// storage. The buffer flushes on the stats tick and at the end.
	save := q.Get("save") == "1" || q.Get("save") == "true"
	var buf []store.Event
	const maxSaved = 20000
	saved := 0
	flush := func() {
		if len(buf) == 0 {
			return
		}
		batch := buf
		buf = nil
		if _, err := s.Store.InsertEvents(context.Background(), batch); err != nil {
			s.Log.Warn("could not persist captured packets", "err", err)
		}
	}
	if save {
		defer flush()
	}

	// Batch SSE writes: packets accumulate and are flushed as one block
	// every 50 packets or on the 1s stats tick, instead of one marshal and
	// flush per packet.
	var batch []recon.Packet
	flushBatch := func() {
		if len(batch) == 0 {
			return
		}
		for _, bp := range batch {
			b, _ := json.Marshal(bp)
			fmt.Fprintf(w, "event: packet\ndata: %s\n\n", b)
		}
		batch = nil
		flusher.Flush()
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case p, ok := <-sess.C:
			if !ok {
				flushBatch()
				if save {
					flush()
				}
				end, _ := json.Marshal(map[string]any{"total": sess.Total(), "saved": saved, "error": sess.Err()})
				fmt.Fprintf(w, "event: end\ndata: %s\n\n", end)
				flusher.Flush()
				return
			}
			if save && saved < maxSaved {
				buf = append(buf, packetEvent(sess.Iface, p))
				saved++
			}
			batch = append(batch, p)
			if len(batch) >= 50 {
				flushBatch()
			}
		case <-stats.C:
			flushBatch()
			if save {
				flush()
			}
			fmt.Fprintf(w, "event: stats\ndata: {\"total\":%d,\"saved\":%d,\"ts\":%d}\n\n", sess.Total(), saved, time.Now().UnixMilli())
			flusher.Flush()
		}
	}
}

// packetEvent maps a captured packet to a searchable event.
func packetEvent(iface string, p recon.Packet) store.Event {
	fields := map[string]string{
		"iface": iface, "src_ip": p.SrcIP, "dst_ip": p.DstIP, "proto": p.Protocol,
		"src_port": p.SrcPort, "dst_port": p.DstPort, "length": strconv.Itoa(p.Length),
		"src_mac": p.SrcMAC, "dst_mac": p.DstMAC,
	}
	host := p.SNI
	if host == "" {
		host = p.DNSQuery
	}
	if host == "" {
		host = p.HTTPHost
	}
	if host != "" {
		fields["app_host"] = host
	}
	t := time.Now().UTC()
	if p.TimeMs > 0 {
		t = time.UnixMilli(p.TimeMs).UTC()
	}
	raw := fmt.Sprintf("%s:%s > %s:%s proto=%s len=%d", p.SrcIP, p.SrcPort, p.DstIP, p.DstPort, p.Protocol, p.Length)
	if host != "" {
		raw += " host=" + host
	}
	return store.Event{
		Time: t, Index: "network", Host: p.SrcIP, Source: iface, Sourcetype: "packet",
		Raw: raw, Fields: fields,
	}
}
