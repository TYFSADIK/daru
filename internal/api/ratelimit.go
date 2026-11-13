package api

import (
	"sync"
	"time"
)

const (
	// loginMaxFailures is how many failed logins are tolerated in one
	// window before the account and address combination is locked out.
	loginMaxFailures = 5
	// loginWindow is the window failed logins are counted in.
	loginWindow = 15 * time.Minute
	// loginMaxBackoff caps the exponential lockout after repeated failures.
	loginMaxBackoff = 2 * time.Hour
)

// loginLimiter tracks failed logins per IP plus username key. After
// loginMaxFailures failures in loginWindow the key is locked out, with the
// lockout doubling on each further failure up to loginMaxBackoff.
type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginAttempt
}

type loginAttempt struct {
	failures    int
	windowStart time.Time
	lockUntil   time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{entries: map[string]*loginAttempt{}}
}

// allowed reports whether a login attempt may proceed, and how long the
// caller must wait when it may not. A nil limiter allows everything, so a
// Server used without Handler still works.
func (l *loginLimiter) allowed(key string) (bool, time.Duration) {
	if l == nil {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.entries[key]
	if !ok {
		return true, 0
	}
	now := time.Now()
	if !a.lockUntil.IsZero() && now.Before(a.lockUntil) {
		return false, time.Until(a.lockUntil)
	}
	if now.Sub(a.windowStart) > loginWindow {
		delete(l.entries, key)
		return true, 0
	}
	return true, 0
}

// recordFailure counts a failed login. The first failure opens the window;
// reaching loginMaxFailures locks the key out for loginWindow, doubling on
// each further failure.
func (l *loginLimiter) recordFailure(key string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	a, ok := l.entries[key]
	if !ok || now.Sub(a.windowStart) > loginWindow {
		a = &loginAttempt{failures: 1, windowStart: now}
		l.entries[key] = a
		return
	}
	a.failures++
	if a.failures >= loginMaxFailures {
		extra := a.failures - loginMaxFailures
		backoff := loginWindow << extra
		if backoff > loginMaxBackoff {
			backoff = loginMaxBackoff
		}
		a.lockUntil = now.Add(backoff)
	}
}

// recordSuccess clears the failure history for a key.
func (l *loginLimiter) recordSuccess(key string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}
