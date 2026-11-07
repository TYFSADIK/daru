// Command daru is a self-hosted log analytics and SIEM platform. One binary
// runs the search API, ingest endpoints, alert scheduler, and web UI against a
// ClickHouse backend.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/TYFSADIK/daru/internal/alerts"
	"github.com/TYFSADIK/daru/internal/api"
	"github.com/TYFSADIK/daru/internal/auth"
	"github.com/TYFSADIK/daru/internal/ingest"
	"github.com/TYFSADIK/daru/internal/search"
	"github.com/TYFSADIK/daru/internal/store"
	"github.com/TYFSADIK/daru/internal/web"
)

const version = "0.1.0"

type config struct {
	listen    string
	chURL     string
	chDB      string
	chUser    string
	chPass    string
	secure    bool
	adminUser string
	adminPass string
}

func loadConfig() config {
	return config{
		listen:    env("DARU_LISTEN", ":8088"),
		chURL:     env("DARU_CLICKHOUSE_URL", "http://localhost:8123"),
		chDB:      env("DARU_CLICKHOUSE_DB", "daru"),
		chUser:    env("DARU_CLICKHOUSE_USER", "default"),
		chPass:    env("DARU_CLICKHOUSE_PASSWORD", ""),
		secure:    env("DARU_SECURE_COOKIES", "") == "true",
		adminUser: env("DARU_ADMIN_USER", ""),
		adminPass: env("DARU_ADMIN_PASSWORD", ""),
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if len(os.Args) < 2 {
		serve(log)
		return
	}
	switch os.Args[1] {
	case "serve":
		serve(log)
	case "migrate":
		migrate(log)
	case "useradd":
		useradd(log, os.Args[2:])
	case "version", "-version", "--version":
		fmt.Println("daru", version)
	case "help", "-h", "--help":
		usage()
	default:
		// Unknown first arg: treat as serve with flags.
		serve(log)
	}
}

func usage() {
	fmt.Print(`daru ` + version + ` - self-hosted log analytics and SIEM

Usage:
  daru serve                 Run the server (default)
  daru migrate               Create the database schema and exit
  daru useradd -u NAME -p PASS -role admin|power|user
  daru version

Configuration (environment variables):
  DARU_LISTEN                Listen address (default :8088)
  DARU_CLICKHOUSE_URL        ClickHouse HTTP URL (default http://localhost:8123)
  DARU_CLICKHOUSE_DB         Database name (default daru)
  DARU_CLICKHOUSE_USER       ClickHouse user (default default)
  DARU_CLICKHOUSE_PASSWORD   ClickHouse password
  DARU_ADMIN_USER            Bootstrap admin username, created on first run
  DARU_ADMIN_PASSWORD        Bootstrap admin password
  DARU_SECURE_COOKIES        Set to "true" when serving behind HTTPS
`)
}

func newStore(cfg config) *store.Store {
	return store.New(store.Config{
		URL: cfg.chURL, Database: cfg.chDB, User: cfg.chUser, Password: cfg.chPass,
	})
}

func migrate(log *slog.Logger) {
	cfg := loadConfig()
	st := newStore(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := waitForStore(ctx, st, log); err != nil {
		fatal(log, "clickhouse not reachable", err)
	}
	if err := st.Migrate(ctx); err != nil {
		fatal(log, "migrate failed", err)
	}
	log.Info("schema is up to date")
}

func useradd(log *slog.Logger, args []string) {
	fs := flag.NewFlagSet("useradd", flag.ExitOnError)
	username := fs.String("u", "", "username")
	password := fs.String("p", "", "password")
	role := fs.String("role", "user", "role: admin, power, or user")
	email := fs.String("email", "", "email (optional)")
	fs.Parse(args)
	if *username == "" || *password == "" {
		fatal(log, "useradd needs -u and -p", nil)
	}
	cfg := loadConfig()
	st := newStore(cfg)
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		fatal(log, "migrate failed", err)
	}
	am := auth.New(st)
	if _, err := am.CreateUser(ctx, *username, *password, *role, *email); err != nil {
		fatal(log, "create user failed", err)
	}
	log.Info("user created", "username", *username, "role", *role)
}

func serve(log *slog.Logger) {
	cfg := loadConfig()
	st := newStore(cfg)
	ctx := context.Background()

	wctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := waitForStore(wctx, st, log); err != nil {
		fatal(log, "clickhouse not reachable", err)
	}
	if err := st.Migrate(ctx); err != nil {
		fatal(log, "migrate failed", err)
	}

	am := auth.New(st)
	bootstrapAdmin(ctx, am, st, cfg, log)

	srv := &api.Server{
		Store:  st,
		Auth:   am,
		Ingest: ingest.New(st),
		Search: search.New(st),
		Log:    log,
		Web:    web.Handler(),
		Secure: cfg.secure,
	}

	sched := alerts.NewScheduler(st, search.New(st), log)
	go sched.Run(ctx)

	httpServer := &http.Server{
		Addr:              cfg.listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
	}

	go func() {
		log.Info("daru listening", "addr", cfg.listen, "version", version)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fatal(log, "server failed", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Info("shutting down")
	shutdownCtx, cancel2 := context.WithTimeout(ctx, 10*time.Second)
	defer cancel2()
	httpServer.Shutdown(shutdownCtx)
}

func waitForStore(ctx context.Context, st *store.Store, log *slog.Logger) error {
	var lastErr error
	for {
		if err := st.Ping(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return lastErr
		case <-time.After(2 * time.Second):
			log.Info("waiting for clickhouse", "url_err", short(lastErr))
		}
	}
}

// bootstrapAdmin creates the first admin from env, or prints one if no users
// exist and none was configured.
func bootstrapAdmin(ctx context.Context, am *auth.Manager, st *store.Store, cfg config, log *slog.Logger) {
	if err := st.EnsureIndex(ctx, "main", 90); err != nil {
		log.Warn("could not ensure main index", "err", err)
	}
	count, err := am.CountUsers(ctx)
	if err != nil {
		log.Warn("could not count users", "err", err)
		return
	}
	if count > 0 {
		return
	}
	if cfg.adminUser != "" && cfg.adminPass != "" {
		if _, err := am.CreateUser(ctx, cfg.adminUser, cfg.adminPass, auth.RoleAdmin, ""); err != nil {
			log.Warn("could not create bootstrap admin", "err", err)
			return
		}
		log.Info("created bootstrap admin", "username", cfg.adminUser)
		return
	}
	log.Warn("no users exist; create one with: daru useradd -u admin -p <password> -role admin, or set DARU_ADMIN_USER and DARU_ADMIN_PASSWORD")
}

func short(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

func fatal(log *slog.Logger, msg string, err error) {
	if err != nil {
		log.Error(msg, "err", err)
	} else {
		log.Error(msg)
	}
	os.Exit(1)
}
