package api

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TYFSADIK/daru/internal/ingest"
	"github.com/TYFSADIK/daru/internal/store"
)

// SyslogConfig configures the syslog receiver. Each address is optional;
// an empty one leaves that transport off.
type SyslogConfig struct {
	UDPAddr string       // e.g. ":5514"
	TCPAddr string       // e.g. ":5514"
	Index   string       // default "syslog"
	Allow   []*net.IPNet // senders allowed; empty allows every sender
}

const (
	syslogMaxMessage = 64 * 1024        // longer messages are cut here
	syslogMaxConns   = 512              // concurrent TCP senders
	syslogIdle       = 10 * time.Minute // a silent TCP sender is dropped
	syslogBatch      = 1000             // events per insert
)

// ServeSyslog receives syslog over UDP and/or TCP until ctx ends. Messages
// share the HTTP ingest rate limit and land in cfg.Index with facility,
// severity, app, and key=value fields extracted. It returns once the
// listeners are open, or with the error that stopped one opening.
func (s *Server) ServeSyslog(ctx context.Context, cfg SyslogConfig) error {
	s.initLimits()
	if cfg.Index == "" {
		cfg.Index = "syslog"
	}
	if err := s.Store.RegisterIndex(ctx, cfg.Index, 90); err != nil {
		return err
	}
	events := make(chan store.Event, 20000)
	go s.syslogWriter(ctx, events)

	accept := func(peer net.IP) bool {
		if len(cfg.Allow) == 0 {
			return true
		}
		for _, n := range cfg.Allow {
			if n.Contains(peer) {
				return true
			}
		}
		return false
	}
	deliver := func(line, peer string) {
		line = strings.TrimRight(line, "\r\n\x00")
		if strings.TrimSpace(line) == "" {
			return
		}
		select {
		case events <- ingest.SyslogEvent(line, peer, cfg.Index, time.Now()):
			s.metrics.syslogReceived.Add(1)
		default:
			s.metrics.syslogDropped.Add(1) // writer is behind (ClickHouse slow or down)
		}
	}

	if cfg.UDPAddr != "" {
		pc, err := net.ListenPacket("udp", cfg.UDPAddr)
		if err != nil {
			return err
		}
		go func() { <-ctx.Done(); _ = pc.Close() }()
		go s.serveSyslogUDP(pc, accept, deliver)
		s.Log.Info("syslog listening", "transport", "udp", "addr", pc.LocalAddr().String(), "index", cfg.Index, "allow", len(cfg.Allow))
	}
	if cfg.TCPAddr != "" {
		ln, err := net.Listen("tcp", cfg.TCPAddr)
		if err != nil {
			return err
		}
		go func() { <-ctx.Done(); _ = ln.Close() }()
		go s.serveSyslogTCP(ctx, ln, accept, deliver)
		s.Log.Info("syslog listening", "transport", "tcp", "addr", ln.Addr().String(), "index", cfg.Index, "allow", len(cfg.Allow))
	}
	if len(cfg.Allow) == 0 {
		s.Log.Warn("syslog accepts every sender; set DARU_SYSLOG_ALLOW to the networks that may send logs")
	}
	return nil
}

func (s *Server) serveSyslogUDP(pc net.PacketConn, accept func(net.IP) bool, deliver func(string, string)) {
	buf := make([]byte, syslogMaxMessage)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok || !accept(ua.IP) {
			s.metrics.syslogDropped.Add(1)
			continue
		}
		// One message per datagram, but some senders pack several lines.
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			deliver(line, ua.IP.String())
		}
	}
}

func (s *Server) serveSyslogTCP(ctx context.Context, ln net.Listener, accept func(net.IP) bool, deliver func(string, string)) {
	sem := make(chan struct{}, syslogMaxConns)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		ta, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok || !accept(ta.IP) {
			s.metrics.syslogDropped.Add(1)
			_ = conn.Close()
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			s.Log.Warn("syslog connection limit reached, refusing sender", "peer", ta.IP.String(), "limit", syslogMaxConns)
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() { _ = conn.Close() }()
			stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer stop()
			readSyslogStream(conn, func(line string) { deliver(line, ta.IP.String()) })
		}()
	}
}

// readSyslogStream reads one TCP syslog stream. Each frame is either
// octet counted ("LEN SP MSG", RFC 6587) or newline terminated; senders
// pick one, and the first byte of each frame tells them apart.
func readSyslogStream(conn net.Conn, emit func(string)) {
	r := bufio.NewReaderSize(conn, syslogMaxMessage)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(syslogIdle))
		b, err := r.Peek(1)
		if err != nil {
			return
		}
		if b[0] >= '1' && b[0] <= '9' {
			lenStr, err := r.ReadString(' ')
			if err != nil || len(lenStr) > 7 {
				return
			}
			n, err := strconv.Atoi(strings.TrimSpace(lenStr))
			if err != nil || n <= 0 {
				return
			}
			keep := min(n, syslogMaxMessage)
			msg := make([]byte, keep)
			if _, err := io.ReadFull(r, msg); err != nil {
				return
			}
			if n > keep {
				if _, err := r.Discard(n - keep); err != nil {
					return
				}
			}
			emit(string(msg))
			continue
		}
		line, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// Over-long line: keep the first 64 KB, skip to the newline.
			emit(string(line))
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = r.ReadSlice('\n')
			}
			if err != nil {
				return
			}
			continue
		}
		if len(line) > 0 {
			emit(string(line))
		}
		if err != nil {
			return
		}
	}
}

// syslogWriter batches received events into ClickHouse, under the same
// events-per-second limit as HTTP ingest.
func (s *Server) syslogWriter(ctx context.Context, events <-chan store.Event) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var batch []store.Event
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if ok, _ := s.ingestLimit.take(len(batch)); !ok {
			s.metrics.ingestRejected.Add(uint64(len(batch))) // #nosec G115 -- a slice length is non-negative
			s.metrics.syslogDropped.Add(uint64(len(batch)))  // #nosec G115 -- a slice length is non-negative
			batch = batch[:0]
			return
		}
		wctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		n, err := s.Ingest.Write(wctx, batch)
		cancel()
		if err != nil {
			s.Log.Error("could not store syslog events", "count", len(batch), "err", err)
			s.metrics.syslogDropped.Add(uint64(len(batch))) // #nosec G115 -- a slice length is non-negative
		} else {
			s.metrics.ingestEvents.Add(uint64(n)) // #nosec G115 -- n is a non-negative event count
		}
		batch = batch[:0]
	}
	for {
		select {
		case ev := <-events:
			batch = append(batch, ev)
			if len(batch) >= syslogBatch {
				flush()
			}
		case <-tick.C:
			flush()
		case <-ctx.Done():
			// Drain what is already queued, then stop.
			for {
				select {
				case ev := <-events:
					batch = append(batch, ev)
					if len(batch) >= syslogBatch {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}
