// Command daru is a self-hosted log analytics and SIEM platform. One binary
// runs the search API, ingest endpoints, alert scheduler, and web UI against a
// ClickHouse backend.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/TYFSADIK/daru/internal/alerts"
	"github.com/TYFSADIK/daru/internal/api"
	"github.com/TYFSADIK/daru/internal/auth"
	"github.com/TYFSADIK/daru/internal/ingest"
	"github.com/TYFSADIK/daru/internal/recon"
	"github.com/TYFSADIK/daru/internal/search"
	"github.com/TYFSADIK/daru/internal/store"
	"github.com/TYFSADIK/daru/internal/web"
)

var version = "0.2.0"

type config struct {
	listen            string
	chURL             string
	chDB              string
	chUser            string
	chPass            string
	secure            bool
	tlsCert           string
	tlsKey            string
	externalAllowlist string
	adminUser         string
	adminPass         string
	chAdminUser       string
	chAdminPass       string
	webhookSecret     string
	metricsToken      string
	ingestMaxEPS      int
	scanConcurrent    int
	scanPerHour       int
	schedulesPerUser  int
	oidc              oidcConfig
}

type oidcConfig struct {
	issuer, clientID, clientSecret, redirectURL, usernameClaim string
	allowedDomains                                             []string
	autoCreate                                                 bool
	defaultRole, defaultIndexes                                string
}

// envInt reads an integer limit. Unset or invalid means 0, which the API
// treats as "use the default"; a negative value disables the limit.
func envInt(key string, log *slog.Logger) int {
	v := os.Getenv(key)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		if log != nil {
			log.Warn("ignoring non-integer limit, using the default", "var", key, "value", v)
		}
		return 0
	}
	return n
}

func loadConfig() config {
	cfg := config{
		listen:            env("DARU_LISTEN", "127.0.0.1:8088"),
		chURL:             env("DARU_CLICKHOUSE_URL", "http://127.0.0.1:8123"),
		chDB:              env("DARU_CLICKHOUSE_DB", "daru"),
		chUser:            env("DARU_CLICKHOUSE_USER", "default"),
		chPass:            env("DARU_CLICKHOUSE_PASSWORD", ""),
		tlsCert:           env("DARU_TLS_CERT", ""),
		tlsKey:            env("DARU_TLS_KEY", ""),
		externalAllowlist: env("DARU_EXTERNAL_ALLOWLIST", ""),
		adminUser:         env("DARU_ADMIN_USER", ""),
		adminPass:         env("DARU_ADMIN_PASSWORD", ""),
		chAdminUser:       env("DARU_CLICKHOUSE_ADMIN_USER", ""),
		chAdminPass:       env("DARU_CLICKHOUSE_ADMIN_PASSWORD", ""),
		webhookSecret:     env("DARU_WEBHOOK_SECRET", ""),
		metricsToken:      env("DARU_METRICS_TOKEN", ""),
		ingestMaxEPS:      envInt("DARU_INGEST_MAX_EPS", nil),
		scanConcurrent:    envInt("DARU_SCAN_CONCURRENT_PER_USER", nil),
		scanPerHour:       envInt("DARU_SCAN_PER_HOUR_PER_USER", nil),
		schedulesPerUser:  envInt("DARU_SCHEDULES_PER_USER", nil),
		oidc: oidcConfig{
			issuer:         env("DARU_OIDC_ISSUER", ""),
			clientID:       env("DARU_OIDC_CLIENT_ID", ""),
			clientSecret:   env("DARU_OIDC_CLIENT_SECRET", ""),
			redirectURL:    env("DARU_OIDC_REDIRECT_URL", ""),
			usernameClaim:  env("DARU_OIDC_USERNAME_CLAIM", "email"),
			autoCreate:     env("DARU_OIDC_AUTO_CREATE", "") == "true",
			defaultRole:    env("DARU_OIDC_DEFAULT_ROLE", auth.RoleUser),
			defaultIndexes: env("DARU_OIDC_DEFAULT_INDEXES", ""),
		},
	}
	for _, d := range strings.Split(env("DARU_OIDC_ALLOWED_DOMAINS", ""), ",") {
		if d = strings.TrimSpace(d); d != "" {
			cfg.oidc.allowedDomains = append(cfg.oidc.allowedDomains, d)
		}
	}
	// Cookies are Secure whenever TLS is on, not only when the flag is set.
	cfg.secure = env("DARU_SECURE_COOKIES", "") == "true" || (cfg.tlsCert != "" && cfg.tlsKey != "")
	return cfg
}

var knownDefaultPasswords = []string{"change-me-admin", "change-me-clickhouse", "change-me", "admin", "password"}

// validateSecrets refuses to start with a password that was ever published
// as a default. An empty admin password is only fatal when a bootstrap
// admin was requested without one; an empty ClickHouse password is allowed
// for a loopback ClickHouse with no password set, but warned about loudly
// when ClickHouse is remote.
func validateSecrets(cfg config, log *slog.Logger) {
	for _, p := range knownDefaultPasswords {
		if cfg.adminPass != "" && cfg.adminPass == p {
			fatal(log, "refusing to start: DARU_ADMIN_PASSWORD is a published default password", nil)
		}
		if cfg.chPass != "" && cfg.chPass == p {
			fatal(log, "refusing to start: DARU_CLICKHOUSE_PASSWORD is a published default password", nil)
		}
		if cfg.chAdminPass != "" && cfg.chAdminPass == p {
			fatal(log, "refusing to start: DARU_CLICKHOUSE_ADMIN_PASSWORD is a published default password", nil)
		}
		if cfg.webhookSecret != "" && cfg.webhookSecret == p {
			fatal(log, "refusing to start: DARU_WEBHOOK_SECRET is a published default", nil)
		}
	}
	if cfg.adminUser != "" && cfg.adminPass == "" {
		fatal(log, "refusing to start: DARU_ADMIN_USER is set but DARU_ADMIN_PASSWORD is empty", nil)
	}
	if cfg.chAdminUser != "" && cfg.chAdminUser == cfg.chUser {
		log.Warn("DARU_CLICKHOUSE_ADMIN_USER equals DARU_CLICKHOUSE_USER; schema rights are not split")
	}
	if cfg.webhookSecret != "" && len(cfg.webhookSecret) < 16 {
		fatal(log, "refusing to start: DARU_WEBHOOK_SECRET must be at least 16 characters", nil)
	}
	if cfg.metricsToken != "" && len(cfg.metricsToken) < 16 {
		fatal(log, "refusing to start: DARU_METRICS_TOKEN must be at least 16 characters", nil)
	}
	if cfg.chPass == "" && !chHostIsLoopback(cfg.chURL) {
		log.Warn("WARNING: ClickHouse password is empty and ClickHouse is not on loopback; credentials cross the network in cleartext over plain HTTP")
	}
}

// isLoopbackListen reports whether the listen address only accepts local
// connections. An empty host (":8088") listens on all interfaces.
func isLoopbackListen(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// chHostIsLoopback reports whether a ClickHouse URL points at loopback.
func chHostIsLoopback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
  DARU_LISTEN                Listen address (default 127.0.0.1:8088)
  DARU_TLS_CERT              TLS certificate file; with DARU_TLS_KEY enables HTTPS
  DARU_TLS_KEY               TLS private key file
  DARU_CLICKHOUSE_URL        ClickHouse URL (default http://127.0.0.1:8123; use https:// for a remote server)
  DARU_CLICKHOUSE_DB         Database name (default daru)
  DARU_CLICKHOUSE_USER       ClickHouse app user: SELECT, INSERT, ALTER DELETE (default default)
  DARU_CLICKHOUSE_PASSWORD   ClickHouse app password (required; never use a published default)
  DARU_CLICKHOUSE_ADMIN_USER ClickHouse user for schema changes and retention drops (default: app user)
  DARU_CLICKHOUSE_ADMIN_PASSWORD  Password for the admin user
  DARU_ADMIN_USER            Bootstrap admin username, created on first run
  DARU_ADMIN_PASSWORD        Bootstrap admin password (required when DARU_ADMIN_USER is set)
  DARU_SECURE_COOKIES        Set to "true" when serving behind HTTPS
  DARU_EXTERNAL_ALLOWLIST    Comma list of external targets allowed for recon, empty means gate only
  DARU_ALLOW_TOOL_UPDATE     Set to "true" to enable POST /api/admin/update-tools
  DARU_ALLOW_ROOT_UPDATE     Set to "1" to allow tool updates while running as root
  DARU_WEBHOOK_SECRET        HMAC-SHA256 key for alert webhooks (X-Daru-Signature), 16+ chars
  DARU_METRICS_TOKEN         Bearer token for /metrics; unset serves /metrics to loopback only
  DARU_INGEST_MAX_EPS        Ingest limit in events/second for the deployment (default 50000, -1 disables)
  DARU_REPLICAS              Number of Daru servers sharing that limit (each enforces its share)
  DARU_SCAN_CONCURRENT_PER_USER  Running recon scans per user (default 2, -1 disables)
  DARU_SCAN_PER_HOUR_PER_USER    Recon scans started per user per hour (default 30, -1 disables)
  DARU_SCHEDULES_PER_USER    Scheduled scans owned per user (default 20, -1 disables)

Single sign on (OIDC, authorization code flow with PKCE):
  DARU_OIDC_ISSUER           Provider issuer URL; setting it enables SSO
  DARU_OIDC_CLIENT_ID        Client id registered at the provider
  DARU_OIDC_CLIENT_SECRET    Client secret
  DARU_OIDC_REDIRECT_URL     https://<daru host>/api/oidc/callback
  DARU_OIDC_USERNAME_CLAIM   email (default), preferred_username, or sub
  DARU_OIDC_ALLOWED_DOMAINS  Comma list of email domains allowed to sign in
  DARU_OIDC_AUTO_CREATE      "true" creates accounts on first sign in (default off)
  DARU_OIDC_DEFAULT_ROLE     Role for auto created accounts (default user)
  DARU_OIDC_DEFAULT_INDEXES  Index access for auto created accounts: "*" or a comma list (default none)

Directory sign in (LDAP; the password form tries the directory after local accounts):
  DARU_LDAP_URL              ldaps://host:636, or ldap://host:389 with DARU_LDAP_STARTTLS=true
  DARU_LDAP_BIND_DN          Service account DN used to search for users
  DARU_LDAP_BIND_PASSWORD    Service account password
  DARU_LDAP_BASE_DN          Search base for users
  DARU_LDAP_USER_FILTER      Default (uid=%s); Active Directory: (sAMAccountName=%s)
  DARU_LDAP_CA_FILE          PEM CA bundle for the directory's certificate
  DARU_LDAP_ADMIN_GROUP      Group DN mapped to admin (with POWER_GROUP, roles follow groups)
  DARU_LDAP_POWER_GROUP      Group DN mapped to power
  DARU_LDAP_AUTO_CREATE, DARU_LDAP_DEFAULT_ROLE, DARU_LDAP_DEFAULT_INDEXES  As for OIDC

SAML 2.0 single sign on:
  DARU_SAML_ROOT_URL         https://<daru host>; SP metadata is served at /api/saml/metadata
  DARU_SAML_IDP_METADATA_URL IdP metadata URL (or DARU_SAML_IDP_METADATA_FILE)
  DARU_SAML_SP_KEY, DARU_SAML_SP_CERT  SP signing key and certificate (PEM)
  DARU_SAML_USERNAME_ATTR    Attribute for the username (default: the NameID)
  DARU_SAML_GROUP_ATTR       Attribute holding groups (default groups)
  DARU_SAML_ADMIN_GROUP, DARU_SAML_POWER_GROUP  Group values mapped to roles
  DARU_SAML_UNSIGNED_REQUESTS  "true" stops signing AuthnRequests (responses are always verified)
  DARU_SAML_AUTO_CREATE, DARU_SAML_DEFAULT_ROLE, DARU_SAML_DEFAULT_INDEXES  As for OIDC

Probes:
  GET /api/health            Liveness: the process answers
  GET /ready                 Readiness: 200 only when ClickHouse answers
  GET /metrics               Prometheus metrics (see DARU_METRICS_TOKEN)
`)
}

func newStore(cfg config) *store.Store {
	return store.New(store.Config{
		URL: cfg.chURL, Database: cfg.chDB, User: cfg.chUser, Password: cfg.chPass,
		AdminUser: cfg.chAdminUser, AdminPassword: cfg.chAdminPass,
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
	_ = fs.Parse(args) // ExitOnError: a bad flag exits before returning
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
	if (cfg.tlsCert == "") != (cfg.tlsKey == "") {
		fatal(log, "DARU_TLS_CERT and DARU_TLS_KEY must be set together", nil)
	}
	validateSecrets(cfg, log)
	if cfg.tlsCert == "" && !isLoopbackListen(cfg.listen) {
		log.Warn("WARNING: serving plain HTTP on a non-loopback address; passwords, session cookies and HEC tokens cross the network in cleartext. Bind DARU_LISTEN to 127.0.0.1 or set DARU_TLS_CERT and DARU_TLS_KEY.")
	}
	if strings.HasPrefix(cfg.chURL, "http://") && !chHostIsLoopback(cfg.chURL) {
		log.Warn("WARNING: ClickHouse URL is plain HTTP to a remote host; the ClickHouse user and password cross the network in cleartext. Use https:// for a remote ClickHouse.")
	}
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
	if cfg.externalAllowlist != "" {
		var entries []string
		for _, e := range strings.Split(cfg.externalAllowlist, ",") {
			if e = strings.TrimSpace(e); e != "" {
				entries = append(entries, e)
			}
		}
		recon.SetExternalAllowlist(entries)
		log.Info("external recon allowlist loaded", "entries", len(entries))
	}

	// Expired and revoked sessions accumulate in ClickHouse forever unless
	// something deletes them. Purge hourly.
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for range t.C {
			if err := am.PurgeExpired(ctx); err != nil {
				log.Warn("session purge failed", "err", err)
			}
		}
	}()

	srv := &api.Server{
		Store:  st,
		Auth:   am,
		Ingest: ingest.New(st),
		Search: search.New(st),
		Log:    log,
		Web:    web.Handler(),
		Secure: cfg.secure,

		IngestMaxEPS:          cfg.ingestMaxEPS,
		Replicas:              envInt("DARU_REPLICAS", log),
		ScanConcurrentPerUser: cfg.scanConcurrent,
		ScanPerHourPerUser:    cfg.scanPerHour,
		SchedulesPerUser:      cfg.schedulesPerUser,
		MetricsToken:          cfg.metricsToken,
	}
	if st.SplitPrivileges() {
		log.Info("clickhouse privileges split", "app_user", cfg.chUser, "admin_user", cfg.chAdminUser)
	} else {
		log.Warn("clickhouse privileges not split: one user runs both DDL and reads; set DARU_CLICKHOUSE_ADMIN_USER and use a least privilege DARU_CLICKHOUSE_USER (see deploy/clickhouse-users.sql)")
	}

	if cfg.oidc.issuer != "" {
		srv.OIDC = setupOIDC(ctx, cfg.oidc, log)
	}
	if url := os.Getenv("DARU_LDAP_URL"); url != "" {
		srv.LDAP, srv.LDAPPolicy = setupLDAP(url, log)
	}
	if os.Getenv("DARU_SAML_ROOT_URL") != "" {
		srv.SAML = setupSAML(ctx, st, log)
	}

	sched := alerts.NewScheduler(st, search.New(st), log)
	sched.SetWebhookSecret(cfg.webhookSecret)
	sched.IndexScope = func(ctx context.Context, owner string) ([]string, bool, error) {
		return srv.SearchScope(ctx, owner, nil)
	}
	if cfg.webhookSecret == "" {
		log.Info("alert webhooks are unsigned; set DARU_WEBHOOK_SECRET to sign them")
	}
	go sched.Run(ctx)
	go srv.RunScheduler(ctx) // recurring recon scans

	// Syslog receiver (off unless an address is set).
	if udp, tcp := os.Getenv("DARU_SYSLOG_UDP"), os.Getenv("DARU_SYSLOG_TCP"); udp != "" || tcp != "" {
		allow, err := parseCIDRList(os.Getenv("DARU_SYSLOG_ALLOW"))
		if err != nil {
			fatal(log, "invalid DARU_SYSLOG_ALLOW", err)
		}
		if err := srv.ServeSyslog(ctx, api.SyslogConfig{UDPAddr: udp, TCPAddr: tcp, Index: os.Getenv("DARU_SYSLOG_INDEX"), Allow: allow}); err != nil {
			fatal(log, "syslog receiver failed to start", err)
		}
	}
	// Per index retention runs on its own loop, whether or not any alert
	// is scheduled.
	go st.RunRetention(ctx, log, store.RetentionInterval)

	httpServer := &http.Server{
		Addr:              cfg.listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No WriteTimeout on purpose: the live capture SSE stream writes
		// for the whole capture duration, and a global write deadline
		// would kill it.
	}

	go func() {
		if cfg.tlsCert != "" {
			log.Info("daru listening with TLS", "addr", cfg.listen, "version", version)
			if err := httpServer.ListenAndServeTLS(cfg.tlsCert, cfg.tlsKey); err != nil && err != http.ErrServerClosed {
				fatal(log, "server failed", err)
			}
			return
		}
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
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Warn("shutdown did not finish cleanly", "err", err)
	}
	srv.FlushAudit(shutdownCtx)
}

// externalPolicy reads PREFIX_AUTO_CREATE, PREFIX_DEFAULT_ROLE and
// PREFIX_DEFAULT_INDEXES, shared by LDAP and SAML.
func externalPolicy(prefix string, log *slog.Logger) api.ExternalAccountPolicy {
	role := env(prefix+"_DEFAULT_ROLE", auth.RoleUser)
	if !auth.ValidRole(role) {
		fatal(log, prefix+"_DEFAULT_ROLE must be admin, power, or user", nil)
	}
	auto := env(prefix+"_AUTO_CREATE", "") == "true"
	if auto && role == auth.RoleAdmin {
		log.Warn("WARNING: " + prefix + "_AUTO_CREATE gives every new identity the admin role")
	}
	access := auth.AllIndexes
	if raw := env(prefix+"_DEFAULT_INDEXES", ""); raw != auth.AllIndexes {
		var list []string
		for _, ix := range strings.Split(raw, ",") {
			if ix = strings.TrimSpace(ix); ix != "" {
				list = append(list, ix)
			}
		}
		var err error
		if access, err = auth.FormatIndexAccess(false, list); err != nil {
			fatal(log, "invalid "+prefix+"_DEFAULT_INDEXES", err)
		}
	}
	return api.ExternalAccountPolicy{AutoCreate: auto, DefaultRole: role, DefaultIndexAccess: access}
}

func setupLDAP(url string, log *slog.Logger) (*auth.LDAPAuthenticator, api.ExternalAccountPolicy) {
	a, err := auth.NewLDAPAuthenticator(auth.LDAPConfig{
		URL:          url,
		StartTLS:     env("DARU_LDAP_STARTTLS", "") == "true",
		Insecure:     env("DARU_LDAP_INSECURE", "") == "true",
		CAFile:       env("DARU_LDAP_CA_FILE", ""),
		BindDN:       env("DARU_LDAP_BIND_DN", ""),
		BindPassword: env("DARU_LDAP_BIND_PASSWORD", ""),
		BaseDN:       env("DARU_LDAP_BASE_DN", ""),
		UserFilter:   env("DARU_LDAP_USER_FILTER", ""),
		UsernameAttr: env("DARU_LDAP_USERNAME_ATTR", ""),
		EmailAttr:    env("DARU_LDAP_EMAIL_ATTR", ""),
		GroupAttr:    env("DARU_LDAP_GROUP_ATTR", ""),
		AdminGroup:   env("DARU_LDAP_ADMIN_GROUP", ""),
		PowerGroup:   env("DARU_LDAP_POWER_GROUP", ""),
	})
	if err != nil {
		fatal(log, "ldap setup failed", err)
	}
	log.Info("ldap sign in enabled", "url", url)
	return a, externalPolicy("DARU_LDAP", log)
}

func setupSAML(ctx context.Context, st *store.Store, log *slog.Logger) *api.SAMLSettings {
	cfg := api.SAMLConfig{
		RootURL:          env("DARU_SAML_ROOT_URL", ""),
		IDPMetadataURL:   env("DARU_SAML_IDP_METADATA_URL", ""),
		IDPMetadataFile:  env("DARU_SAML_IDP_METADATA_FILE", ""),
		KeyFile:          env("DARU_SAML_SP_KEY", ""),
		CertFile:         env("DARU_SAML_SP_CERT", ""),
		UsernameAttr:     env("DARU_SAML_USERNAME_ATTR", ""),
		EmailAttr:        env("DARU_SAML_EMAIL_ATTR", ""),
		GroupAttr:        env("DARU_SAML_GROUP_ATTR", ""),
		AdminGroup:       env("DARU_SAML_ADMIN_GROUP", ""),
		PowerGroup:       env("DARU_SAML_POWER_GROUP", ""),
		UnsignedRequests: env("DARU_SAML_UNSIGNED_REQUESTS", "") == "true",
		Policy:           externalPolicy("DARU_SAML", log),
	}
	deadline := time.Now().Add(time.Minute)
	for {
		sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		sc, err := api.NewSAML(sctx, cfg, st)
		cancel()
		if err == nil {
			log.Info("saml single sign on enabled", "sp_entity_id", sc.SP.EntityID)
			return sc
		}
		if time.Now().After(deadline) || !strings.Contains(err.Error(), "fetch IdP metadata") {
			fatal(log, "saml setup failed", err)
		}
		log.Warn("saml metadata fetch failed, retrying", "err", err)
		time.Sleep(3 * time.Second)
	}
}

// setupOIDC discovers the provider, retrying for up to a minute so Daru and
// a self hosted provider can start together. A misconfiguration is fatal:
// silently starting without the SSO an operator asked for would be worse.
func setupOIDC(ctx context.Context, oc oidcConfig, log *slog.Logger) api.OIDCSettings {
	if !auth.ValidRole(oc.defaultRole) {
		fatal(log, "DARU_OIDC_DEFAULT_ROLE must be admin, power, or user", nil)
	}
	if oc.autoCreate && oc.defaultRole == auth.RoleAdmin {
		log.Warn("WARNING: DARU_OIDC_AUTO_CREATE gives every new SSO identity the admin role; restrict DARU_OIDC_ALLOWED_DOMAINS")
	}
	access := auth.AllIndexes
	if oc.defaultIndexes != auth.AllIndexes {
		var list []string
		for _, ix := range strings.Split(oc.defaultIndexes, ",") {
			if ix = strings.TrimSpace(ix); ix != "" {
				list = append(list, ix)
			}
		}
		var err error
		if access, err = auth.FormatIndexAccess(false, list); err != nil {
			fatal(log, "invalid DARU_OIDC_DEFAULT_INDEXES", err)
		}
	}
	occ := auth.OIDCConfig{
		Issuer: oc.issuer, ClientID: oc.clientID, ClientSecret: oc.clientSecret,
		RedirectURL: oc.redirectURL, UsernameClaim: oc.usernameClaim, AllowedDomains: oc.allowedDomains,
	}
	deadline := time.Now().Add(time.Minute)
	for {
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		p, err := auth.DiscoverOIDC(dctx, occ)
		cancel()
		if err == nil {
			log.Info("oidc single sign on enabled", "issuer", oc.issuer, "username_claim", p.UsernameClaim(),
				"auto_create", oc.autoCreate, "allowed_domains", strings.Join(oc.allowedDomains, ","))
			return api.OIDCSettings{Provider: p, AutoCreate: oc.autoCreate, DefaultRole: oc.defaultRole, DefaultIndexAccess: access}
		}
		if time.Now().After(deadline) || !strings.Contains(err.Error(), "discovery") {
			fatal(log, "oidc setup failed", err)
		}
		log.Warn("oidc discovery failed, retrying", "err", err)
		time.Sleep(3 * time.Second)
	}
}

func waitForStore(ctx context.Context, st *store.Store, log *slog.Logger) error {
	var lastErr error
	authFails := 0
	for {
		if err := st.Ping(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		// An authentication failure will not resolve by waiting. Retrying a
		// wrong password forever just hides the real problem. Surface it
		// clearly and stop after a couple of confirmations.
		if isAuthError(lastErr) {
			authFails++
			if authFails >= 2 {
				return fmt.Errorf("clickhouse rejected the configured credentials (check DARU_CLICKHOUSE_USER/PASSWORD): %w", lastErr)
			}
			log.Warn("clickhouse authentication failed, check DARU_CLICKHOUSE_PASSWORD", "err", short(lastErr))
		}
		select {
		case <-ctx.Done():
			return lastErr
		case <-time.After(2 * time.Second):
			log.Info("waiting for clickhouse", "url_err", short(lastErr))
		}
	}
}

// isAuthError reports whether a store error is a ClickHouse authentication
// failure (which will not be fixed by retrying).
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "authentication failed") ||
		strings.Contains(s, "password is incorrect") ||
		strings.Contains(s, "code: 516") || strings.Contains(s, "code: 194")
}

// bootstrapAdmin creates the first admin from env, or prints one if no users
// exist and none was configured.
func bootstrapAdmin(ctx context.Context, am *auth.Manager, st *store.Store, cfg config, log *slog.Logger) {
	// Default indexes: main (logs), recon (scan findings), network (captured
	// packets, high volume, so a shorter default retention).
	for _, ix := range []struct {
		name      string
		retention uint32
	}{{"main", 90}, {"recon", 90}, {"network", 7}} {
		// Only when missing: an admin's retention survives restarts.
		if err := st.RegisterIndex(ctx, ix.name, ix.retention); err != nil {
			log.Warn("could not register index", "index", ix.name, "err", err)
		}
	}
	if err := st.RegisterEventIndexes(ctx); err != nil {
		log.Warn("could not register indexes found in events", "err", err)
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

// parseCIDRList reads a comma separated list of CIDR ranges or single IPs.
func parseCIDRList(v string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, fmt.Errorf("%q is not an IP address or CIDR range", part)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			part = fmt.Sprintf("%s/%d", ip.String(), bits)
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address or CIDR range", part)
		}
		out = append(out, n)
	}
	return out, nil
}
