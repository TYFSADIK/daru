package api

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

// Defaults for the server wide limits. Each one can be overridden on the
// Server struct (see cmd/daru for the environment variables).
const (
	DefaultIngestMaxEPS          = 50000 // events per second, all tokens together
	DefaultScanConcurrentPerUser = 2     // running scans per user
	DefaultScanPerHourPerUser    = 30    // scans started per user per hour
	DefaultSchedulesPerUser      = 20    // scheduled scans owned per user

	// maxEventsPerRequest mirrors the per request cap in ingest; the bucket
	// is always at least this deep so one maximum size request can pass
	// when the bucket is full.
	maxEventsPerRequest = 100000
)

// ErrQuota is returned when a per user quota is exhausted.
var ErrQuota = errors.New("quota exceeded")

// ingestLimiter is a global token bucket over events per second. It is
// shared by every ingest token, so one noisy forwarder cannot starve
// ClickHouse, and it is counted in events, not requests, since a single
// HEC request may carry up to 100k events.
type ingestLimiter struct {
	mu       sync.Mutex
	rate     float64 // events per second
	capacity float64
	tokens   float64
	last     time.Time
	now      func() time.Time
}

func newIngestLimiter(eps int) *ingestLimiter {
	if eps <= 0 {
		return nil // unlimited
	}
	capacity := math.Max(float64(eps)*2, maxEventsPerRequest)
	l := &ingestLimiter{rate: float64(eps), capacity: capacity, tokens: capacity, now: time.Now}
	l.last = l.now()
	return l
}

// take admits n events or reports how long until they would fit. A nil
// limiter admits everything.
func (l *ingestLimiter) take(n int) (bool, time.Duration) {
	if l == nil || n <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.tokens = math.Min(l.capacity, l.tokens+now.Sub(l.last).Seconds()*l.rate)
	l.last = now
	need := float64(n)
	if need > l.capacity {
		need = l.capacity
	}
	if l.tokens >= need {
		l.tokens -= need
		return true, 0
	}
	wait := time.Duration((need - l.tokens) / l.rate * float64(time.Second))
	return false, wait
}

// userQuotas bounds how many scans each user runs at once, how many they
// start per hour, and how many scheduled scans they own. Scans launched by
// the scheduler are charged to the user who created the schedule.
type userQuotas struct {
	mu            sync.Mutex
	maxConcurrent int
	maxPerHour    int
	maxSchedules  int
	running       map[string]int
	started       map[string][]time.Time
	now           func() time.Time
}

func newUserQuotas(concurrent, perHour, schedules int) *userQuotas {
	return &userQuotas{
		maxConcurrent: concurrent, maxPerHour: perHour, maxSchedules: schedules,
		running: map[string]int{}, started: map[string][]time.Time{}, now: time.Now,
	}
}

// quotaUser maps a scan's created_by value to the account it is charged to.
func quotaUser(createdBy string) string {
	return strings.TrimPrefix(createdBy, "scheduler:")
}

// acquireScan reserves a scan slot for user. The returned release function
// must be called exactly once when the scan ends.
func (q *userQuotas) acquireScan(createdBy string) (func(), error) {
	if q == nil {
		return func() {}, nil
	}
	user := quotaUser(createdBy)
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	// Drop starts older than an hour.
	recent := q.started[user][:0]
	for _, t := range q.started[user] {
		if now.Sub(t) < time.Hour {
			recent = append(recent, t)
		}
	}
	q.started[user] = recent
	if q.maxConcurrent > 0 && q.running[user] >= q.maxConcurrent {
		return nil, fmt.Errorf("%w: %d scans already running for %s (limit %d)", ErrQuota, q.running[user], user, q.maxConcurrent)
	}
	if q.maxPerHour > 0 && len(recent) >= q.maxPerHour {
		return nil, fmt.Errorf("%w: %d scans started by %s in the last hour (limit %d)", ErrQuota, len(recent), user, q.maxPerHour)
	}
	q.running[user]++
	q.started[user] = append(q.started[user], now)
	var once sync.Once
	return func() {
		once.Do(func() {
			q.mu.Lock()
			defer q.mu.Unlock()
			if q.running[user]--; q.running[user] <= 0 {
				delete(q.running, user)
			}
		})
	}, nil
}

// checkSchedules reports whether user may own one more scheduled scan.
func (q *userQuotas) checkSchedules(user string, owned int) error {
	if q == nil || q.maxSchedules <= 0 {
		return nil
	}
	if owned >= q.maxSchedules {
		return fmt.Errorf("%w: %s already owns %d scheduled scans (limit %d)", ErrQuota, user, owned, q.maxSchedules)
	}
	return nil
}
