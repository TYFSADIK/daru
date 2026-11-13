package store

import (
	"context"
	"log/slog"
	"time"
)

// RetentionInterval is how often RunRetention sweeps expired partitions.
const RetentionInterval = 6 * time.Hour

// RunRetention drops expired event partitions once at start and then every
// interval until ctx is cancelled. It is independent of the alert
// scheduler, so per-index retention is enforced even when no alerts run.
// The events table TTL (90 days) remains as a backstop for indexes whose
// retention is longer than that, and partitions are dropped whole, so the
// sweep is cheap.
func (s *Store) RunRetention(ctx context.Context, log *slog.Logger, interval time.Duration) {
	if interval <= 0 {
		interval = RetentionInterval
	}
	sweep := func() {
		sctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		n, err := s.DropOldPartitions(sctx)
		if err != nil {
			if log != nil {
				log.Warn("retention sweep failed", "err", err)
			}
			return
		}
		if n > 0 && log != nil {
			log.Info("retention sweep dropped partitions", "partitions", n)
		}
	}
	sweep()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweep()
		}
	}
}
