package api

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/TYFSADIK/daru/internal/auth"
)

// aclTTL bounds how long a cached index scope is trusted. Changes made
// through SetIndexAccess invalidate the entry at once; the TTL only covers
// edits made by another Daru process against the same ClickHouse.
const aclTTL = 30 * time.Second

// indexScope is the resolved index ACL for one user.
type indexScope struct {
	all     bool
	allowed map[string]bool
	expires time.Time
}

func (sc indexScope) permits(index string) bool { return sc.all || sc.allowed[index] }

// indexACLCache caches per user index scopes, so a search does not cost an
// extra users lookup every time.
type indexACLCache struct {
	mu      sync.Mutex
	entries map[string]indexScope
}

func newIndexACLCache() *indexACLCache {
	return &indexACLCache{entries: map[string]indexScope{}}
}

func (c *indexACLCache) invalidate(username string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.entries, username)
	c.mu.Unlock()
}

// scopeFor resolves a user's index scope. The role comes from the user
// row, not the session, so a demotion applies on the next request. A user
// that cannot be found gets no indexes: failing closed.
func (s *Server) scopeFor(ctx context.Context, username string) (indexScope, error) {
	s.initLimits()
	c := s.acl
	c.mu.Lock()
	if e, ok := c.entries[username]; ok && time.Now().Before(e.expires) {
		c.mu.Unlock()
		return e, nil
	}
	c.mu.Unlock()
	u, err := s.Auth.GetUser(ctx, username)
	if err != nil {
		return indexScope{}, err
	}
	sc := indexScope{allowed: map[string]bool{}, expires: time.Now().Add(aclTTL)}
	if u != nil && !u.Disabled {
		sc.all, sc.allowed = u.IndexScope()
		if sc.allowed == nil {
			sc.allowed = map[string]bool{}
		}
	}
	c.mu.Lock()
	c.entries[username] = sc
	c.mu.Unlock()
	return sc, nil
}

// SearchScope resolves the indexes a user may search, narrowed to the
// requested subset. It returns the index list to pass to the search
// service and whether that list must be enforced (IndexesSpecified). A
// restricted user always gets an enforced list, even when it is empty, so
// "no permitted index" can never fall through to "every index".
func (s *Server) SearchScope(ctx context.Context, username string, requested []string) ([]string, bool, error) {
	sc, err := s.scopeFor(ctx, username)
	if err != nil {
		return nil, true, err
	}
	all, err := s.Store.ListIndexes(ctx)
	if err != nil {
		return nil, true, err
	}
	want := map[string]bool{}
	for _, r := range requested {
		want[r] = true
	}
	var out []string
	for _, ix := range all {
		if !sc.permits(ix.Name) {
			continue
		}
		if len(requested) > 0 && !want[ix.Name] {
			continue
		}
		out = append(out, ix.Name)
	}
	enforced := len(requested) > 0 || !sc.all
	if out == nil {
		out = []string{}
	}
	return out, enforced, nil
}

// handleSetIndexAccess sets which indexes a user may search.
// Body: {"all": true} or {"indexes": ["main", "web"]}; an empty list
// removes access to every index.
func (s *Server) handleSetIndexAccess(w http.ResponseWriter, r *http.Request) {
	var req struct {
		All     bool     `json:"all"`
		Indexes []string `json:"indexes"`
	}
	if err := readJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	access, err := auth.FormatIndexAccess(req.All, req.Indexes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.checkIndexesExist(r.Context(), access); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	username := r.PathValue("username")
	if err := s.Auth.SetIndexAccess(r.Context(), username, access); err != nil {
		s.Log.Warn("could not set index access", "user", username, "err", err)
		writeError(w, http.StatusBadRequest, "could not set index access")
		return
	}
	s.acl.invalidate(username)
	s.audit(r, "user.index_access", sessionFrom(r.Context()).Username, "target", username, "index_access", access)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "index_access": access})
}

// checkIndexesExist rejects an ACL naming an index that does not exist, so
// a typo cannot silently grant nothing.
func (s *Server) checkIndexesExist(ctx context.Context, access string) error {
	if access == auth.AllIndexes || access == "" {
		return nil
	}
	known, err := s.Store.ListIndexes(ctx)
	if err != nil {
		return fmt.Errorf("could not list indexes")
	}
	have := map[string]bool{}
	for _, ix := range known {
		have[ix.Name] = true
	}
	_, allowed := auth.ParseIndexAccess(auth.RoleUser, access)
	var missing []string
	for ix := range allowed {
		if !have[ix] {
			missing = append(missing, ix)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("unknown index: %v", missing)
	}
	return nil
}
