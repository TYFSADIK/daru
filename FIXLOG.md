# Daru FIXLOG, v0.2.0

Date: 2026-11-08
Baseline: audit HEAD 9c7aa17, branch feat/recon-live-monitor-dashboards, from daru_0_b4xp.zip
Audit report: Daru-Hard-Audit-Report.md (C1 to C7, H1 to H15, M1 to M20, L1 to L9)
This tree: ~/workspace/daru-fixed, git log shows baseline plus one fix commit

## Gates, verified in this tree

- `go vet ./...`: exit 0
- `go test ./... -count=1`: all packages pass, 162 tests run (baseline had 100 test functions)
- `go build ./cmd/daru`: succeeds, binary runs `daru version` as 0.2.0
- `node --check internal/web/static/app.js`: pass
- `bash -n` on install.sh, backup.sh, restore.sh, update-tools.sh: pass
- CI and Dependabot YAML parse: pass
- No em dashes or en dashes remain in Go, JS, MD, HTML, or CSS files in this tree (swept in merge)
- Live ClickHouse was NOT available, so the store integration test still skips, and generated SQL was verified by unit tests only, not by execution. Run `go test ./internal/store/ -run TestRoundTrip` with DARU_TEST_CH set before shipping.
- No live browser was available, so the 360px mobile check was code inspection only. Check it on a real phone after deploy.
- Docker was NOT available here, so `docker build` and `docker compose config` were validated by YAML parsing and CI only, not by running them.

## Critical fixes

- C1: default listen is now 127.0.0.1:8088, TLS via DARU_TLS_CERT and DARU_TLS_KEY with ListenAndServeTLS, Secure cookie whenever TLS is on, loud startup warning for plain HTTP on a non-loopback address and for remote plain HTTP ClickHouse. All change-me defaults removed from compose, compose now fails fast with ${VAR:?msg}, main refuses published default passwords. Note: inside Docker, DARU_LISTEN stays :8088 in the container and host exposure is loopback only via 127.0.0.1:8088:8088 port mapping.
- C2: both schedulers reset to minute.Add(time.Minute) from the wall clock, so odd minutes fire. Alert ticks run concurrently with a per alert 60s timeout. Alert firing uses a dedicated count query (search.Service.Count) or the aggregated stats value, never len(rows). Default window is derived from the cron interval: 5m every minute, 1h hourly, 24h daily, 7d weekly.
- C3: eventstats and streamstats now put OVER on each bare aggregate and wrap scalars outside, for count, dc, range, values, list, mode, sum, avg, median, stdev, earliest, latest, first, and percentiles. Tests cover count, dc, range, values, sum, and avg in both commands.
- C4: update-tools is gated behind DARU_ALLOW_TOOL_UPDATE=true (default off), requires header X-Daru-Confirm: update-tools, refuses to run as root unless DARU_ALLOW_ROOT_UPDATE=1, is audit logged with user, time, and output hash, and tool versions are pinned (nuclei v3.11.1, httpx v1.11.0, subfinder v2.17.0, dnsx v1.3.1, katana v1.8.0, naabu v2.7.0, ffuf v2.3.0). brew upgrade-all replaced with named scanner formulae only.
- C5: login rate limit 5 failures per IP plus username in 15 minutes, then 429 with Retry-After and exponential backoff to 2h, failed logins audit logged, concurrent Login bounded by a 4 slot semaphore, SetPassword revokes all sessions, SetRole revokes on demotion, PurgeExpired runs hourly, VerifyPassword validates Argon2 params, NewToken fails closed on RNG error.
- C6: BPF is passed as one argv element in both tcpdump engines, never strings.Fields. validBPF rejects any token starting with -, and rejects -w, -r, -F, -z, -C, -G, -W.
- C7: guardResolvedHost requires ALL resolved IPs private and fails closed on unresolvable hosts. TgtDomain calls guardHost. Run re-validates immediately before exec and pins the resolved IP. Scheduled scans: ScheduledScan now stores authorization_ref and allow_external in ClickHouse (new columns, added by ALTER on upgrade), the create handler stores the caller supplied reference instead of the "scheduled" placeholder, the tick passes Scheduled: true with the stored reference, and ValidateScheduled rejects external scheduled scans without a real reference, confirmation, and allow_external. Server side external allowlist: DARU_EXTERNAL_ALLOWLIST env, wired in main.go via recon.SetExternalAllowlist. Local scheduled scans need no reference.

## High fixes

- H1: Go 1.27.3 everywhere (go.mod, Dockerfile golang:1.27.3-alpine, CI and release, install.sh, install.ps1, README badge). CI has a version drift check. Version bumped to 0.2.0 in main.go and in the UI footer via make stamp-version. Dockerfile passes -X main.version and has a HEALTHCHECK.
- H2: security headers middleware (CSP default-src self, X-Frame DENY, nosniff, Referrer no-referrer, Permissions-Policy, HSTS when TLS), double submit CSRF token per session for state changing requests plus Origin and Referer checks, login/logout and HEC exempt. Live capture no longer starts on GET: POST /api/live/capture/start issues a one time 5 minute stream token, GET SSE only runs with it. The UI was updated to match: API.call sends X-Daru-CSRF from the daru_csrf cookie, and startCapture POSTs first, then opens EventSource with the token.
- H3: HEC index enforcement on all three ingest paths: per event index must equal tok.DefaultIndex or it is rejected with 403, raw ?index= must match, token default validated with validName.
- H4: ownership enforced in handlers and store: SaveSearch and SaveDashboard check an existing row owner (owner or admin, else 403, else a supplied ID for a missing row is cleared so a new UUID is generated), DeleteSavedSearch, DeleteDashboard, and DeleteScheduledScan check owner or admin. GetSavedSearch added to the store.
- H5: chIdent escapes backtick as backslash backtick, rex group names are validated with checkName and mapped to their true index counting all groups, schema ident() escapes backslash then backtick, DARU_CLICKHOUSE_DB validated against ^[A-Za-z0-9_-]+$ max 64.
- H6: empty earliest defaults to -24h in search.Run and Count, store.do sets max_execution_time=30 and max_rows_to_read=10000000, unknown indexes only now returns an empty result without querying ClickHouse (IndexesSpecified flag, wired in handlers_core.go in merge).
- H7: tshark-pcap path must be under DARU_PCAP_DIR or /tmp/daru-pcap, require .pcap or .pcapng, EvalSymlinks, reject /etc, /dev, /proc and absolute paths outside the allowlist.
- H8: when euid is 0, extraBinDirs excludes user writable dirs and all SUDO_USER paths, candidates must be root owned and never world writable, Run no longer falls back to a bare binary name, every connector now has a verify callback.
- H9: Go downloads verified against official SHA-256 checksums pinned in install.sh and install.ps1, fail closed on mismatch, ARM download name fixed to linux-armv6l, install.sh is bash with set -euo pipefail, unknown flags fail, rand_secret is openssl only (date|sha1sum fallback removed), stored credentials verified on re-run, ClickHouse startup failure fails the install, PowerShell uses RandomNumberGenerator and GetBytes, verifies zip hash and winget/Go, persists PATH, waits for ClickHouse.
- H10: lowercase and, or, not, in now work in the search parser via case insensitive keyword().
- H11: chart with no over/by rejected; timechart and chart limits applied via top-N series subquery and SeriesLimit; tail uses row_number OVER (ORDER BY _time DESC); head sorts by _time DESC first; stats/chart/top/dedup group by raw _time; bin _time numeric span rejected; dropped field references error instead of silently becoming ''; != and NOT IN are null tolerant; isNumeric uses ParseFloat (1e3 and +5 compare numerically); eval x = 5m rejected; rename onto an existing column excepts the target; eval rejects _time, _id, _raw.
- H12: parseHECTime classifies by magnitude (s under 1e11, ms under 1e14, us under 1e17, ns otherwise) and errors out of range instead of storing year 57744 events. ParseHEC accepts a JSON array, fixing handleJSONIngest.
- H13: per-index retention is enforced by DropOldPartitions, dropping whole (index, YYYYMMDD) partitions older than each index retention period, capped at 366 partitions per index, run once a day by the alert scheduler (RunRetentionSweep). EnsureIndex comment now states this, not the table TTL.
- H14: mobile nav hamburger (#nav-toggle) toggles .sidebar.open, closes on route change and Escape, aria-expanded and aria-label updates, skip link, aria-current on active nav, focus to main on route change, login card width min(340px, calc(100vw - 32px)), .table-scroll wrapper with scope=col headers.
- H15: all prompt() and confirm() calls are gone from app.js. Generic openModal dialog (role=dialog, Escape and overlay close, focus on first field) and confirmDialog are used for user create (password type=password, role as select), role change, password reset, index and token create, saved search, dashboard, alert, recon schedule, deep scan, and all destructive deletes. Passwords are never echoed back.

## Medium fixes

- M1: live capture denies lo for power users, DARU_CAPTURE_IFACES allowlist (empty means all except lo), power captures clamp to 300s, admin up to 3600s, packet cap lowered to dur*1000, SSE writes batched (50 packets or 1s tick).
- M2: isPrivateIP is explicit RFC1918 only: 10/8, 172.16/12, 192.168/16, loopback, link-local. No CGNAT 100.64/10, no 198.18/15, no 0.0.0.0.
- M3: targets starting with - rejected, hostnames starting or ending with - or . rejected, -- inserted before positional targets for nmap, fping, unicornscan, nbtscan, traceroute.
- M4: recon semaphore with 10s select timeout returning recon.ErrBusy, mapped to HTTP 429. ReadTimeout 30s and IdleTimeout 120s set (no WriteTimeout on purpose, so SSE capture is not killed). Per token HEC quotas are enforced by the 64 MiB body cap and 100k event cap plus the index check; a global ingest rate limiter was not added, see unfinished.
- M5: every parser capped at 5000 findings via capFindings in runParse and runNative, with a truncation finding.
- M6: CIDR cap lowered to /16 in scope.go, deepScan enforces it and caps discovered hosts at 1024.
- M7: runTool, dnsxRun, and arpScan use capped output (1 MB), zmapRouteParams and defaultGateway use 5s context timeouts.
- M8: ClickHouse least privilege is documented in README and in the fix order, but the runtime user split was NOT implemented in code: the same user still does Migrate DDL and search reads. Do that as a deployment step (create a daru_app user with only SELECT and INSERT, and a separate migrate-only credential), or as the next code change.
- M9: per-index RBAC was NOT implemented. Every authenticated user can still read every index (the comment in handlers_core.go still says so). Ownership checks (H4) are done, index ACLs are not. See unfinished.
- M10: scripts/backup.sh and scripts/restore.sh using ClickHouse BACKUP and RESTORE DATABASE daru, Docker or local clickhouse-client, --help and --dry-run for restore, documented in README with a daily cron example.
- M11: audit logging helper added and called for login success, failure, rate limiting, TOTP required, logout, user create, password, role, disable, index create, token create and disable, TOTP enrol, enable, disable, live capture start, and tool update start, block, and finish, with user and peer IP. /ready and /metrics endpoints were NOT added.
- M12: Daru HEALTHCHECK in Dockerfile, CPU and memory limits guidance in compose, web.go fingerprints app.js with ?v=<hash>, immutable caching on hashed assets, no-cache on index.html, 404 JSON for unknown /api/* and /services/* instead of the SPA shell, handler returns 500 instead of panicking.
- M13: SetNotableStatus preserves raw, ListNotable and InsertNotable carry Raw, SaveSearch and SaveDashboard generate UUID in Go and return the stored id, MarkScheduledScanRun returns an error when the scan is missing.
- M14: InsertFindings uses deterministic UUIDv5 style ids (SHA-256 of scan plus title plus target plus port plus service) and skips findings already stored for that scan. ParseRawStrict checks sc.Err, caps at 100000 events, timestamps per line; handleHECRaw now uses ParseRawStrict and returns 400 on parse error (merge fix). ExtractFields trims deterministically (explicit fields first, then sorted extracted fields) and logs dropped count; FlattenJSON visits keys in sorted order.
- M15: timeparse rejects bare numbers under 9 digits, missing numbers before a unit, and out of range numbers with checked Atoi and a 1 to 100000 bound. Alert conditions and actions are validated strictly at save time (handlers_saved.go fails the save), RecordAlertFire records delivered after notifiers succeed.
- M16: index names validated with validName on every ingest path, InsertEvents chunked at 10000 per INSERT, ListAssets, ListSavedSearches, ListDashboards, and ListScheduledScans all use LIMIT 1000.
- M17: pcap upload uses a random MkdirTemp subdirectory of /tmp/daru-pcap after Lstat rejects a symlinked base, returns 413 when the file exceeds 200 MB. netinfo signal line length check, ffuf empty URL guard, shellQuote escapes single quote as '\''.
- M18: CI adds golangci-lint, govulncheck, gosec, Dependabot, node --check app.js, shell syntax checks, Docker build plus docker compose config smoke test, clean tree check, backup and restore --help checks. Release generates an SBOM (anchore/sbom-action, SPDX) and signs artifacts with cosign. .dockerignore added (.git, docs, dist, daru, .github).
- M19: install.sh pipefail and unknown flag failure, PowerShell PATH persistence and winget verification, CONTRIBUTING make run line fixed, Basalt and BQL renamed to Daru in README and app.js.
- M20: GET /api/system is admin only, unauthenticated /api/health returns only {"status":"ok"}, client errors are generic with ClickHouse detail logged server side, rand.Read errors checked in NewToken, VerifyPassword validates Argon2 params, native OSINT TLS InsecureSkipVerify is kept only for cert inspection and findings are labelled unverified, serve-root.sh does not auto update as root, defaults DARU_LISTEN to 127.0.0.1:8088, refuses wildcard listen unless DARU_ALLOW_PUBLIC_LISTEN=1, only sources the env file when root owned and not group or world writable, hydra and wfuzz removed from install-recon-tools.sh.

## Low fixes

- L1: html branch of el() deleted, esc() also escapes ' and /, device report rebuilt with createElement and textContent only.
- L2: ReconOverview returns Partial: true plus PartialError when TopHosts or RecentHigh fails.
- L3: decodeCell keeps integers as json.Number, no precision loss above 2^53.
- L4: eventColumns derived from returned rows (_time first, then host, source, sourcetype, sorted rest, _raw last).
- L5: field summaries and timechart responses labelled Sampled.
- L6: row mappers check len(r) before indexing.
- L7: cron weekday 7 maps to Sunday, including ranges such as 5-7.
- L8: color-mix now has plain fallback declarations.
- L9: meta description added, robots.txt added, favicon was already logo.svg.

## New tools and features

- Recon: 8 new connectors, all with build, parse, verifier, and tests, total now 51 unique Name entries (42 at audit, plus 8 new, plus posture): rustscan, dalfox, wpscan, assetfinder, waybackurls, gau, hakrawler, trufflehog (git URL target, --only-verified by default). install-recon-tools.sh installs them, grant-capabilities.sh adds rustscan.
- MITRE ATT&CK: Finding gains MitreTactic and MitreTechnique, populated centrally in runParse and runNative from a per-connector map, stored in finding Fields, new native posture connector aggregates MITRE coverage by tactic, saved searches and alerts carry mitre_tactic and mitre_technique (validated TA0000 and T0000 or T0000.000), notable events carry them, and the Security page has a MITRE coverage panel grouping by tactic with an Unmapped bucket.
- TOTP MFA: stdlib only RFC 4226 and 6238 HMAC-SHA1, 30 second step, 6 digits, plus or minus 1 step skew, constant time compare. auth.GenerateTOTPSecret, VerifyTOTP, TOTPProvisioningURI, totp_secret and totp_enabled columns on users (CREATE plus ALTER for upgrades), Login takes an optional TOTP code and requires it when enabled, endpoints POST /api/me/totp/enrol, enable, disable and POST /api/admin/users/{username}/totp/disable, /api/me reports totp_enabled. UI: login form has an optional authenticator code field, Security page has a TOTP card with Enable and Disable flows (merge fix, the API existed but the UI did not call it).
- Alerts: webhook delivery (webhookNotifier, 10s timeout, one retry on network error or 5xx, immediate failure on 4xx, configured per alert via webhook_url in actions JSON), alert dedup and suppression via suppress_minutes in actions JSON checked against LastAlertFire in alert_history, alert condition and actions validated at save time.
- UI: dashboard share link (#/dashboard/<id>, router support, clipboard copy plus modal fallback), Export PDF via window.print() with a print stylesheet, Export CSV per dashboard, saved-search scheduling UI parity (Save search modal with alert toggle, cron, condition, severity, webhook URL, all validated client side).
- Ops: backup and restore scripts, version drift CI check, signed releases with SBOM, Dependabot.

## Follow up, 2026-11-13: every open item from the list above

Each item below was listed as unfinished in v0.2.0. All are now done and
verified, in unit tests and against live ClickHouse 25.8, Docker, Dex (a
real OIDC provider), and headless Chromium.

- Per-index RBAC (M9): `users.index_access` ("*" every index, a comma list,
  or empty for none; upgrades default to "*"). Enforced in `/api/search`,
  `/api/indexes`, and scheduled alerts (run with the owner's access). A
  restricted user always gets an explicit `index IN (...)` filter, so "no
  permitted index" can never fall through to "every index". Admins always
  read everything. Every user row rewrite (password, role, TOTP, disable)
  carries the ACL, so a password change cannot widen access. Admin UI:
  Users > Indexes. API: `POST /api/admin/users/{name}/indexes`, and an
  optional `indexes` list on user creation. Verified live: a user limited
  to `main` sees only `main`, `index=secret` returns nothing, the ACL
  survives a password reset.
- ClickHouse least privilege split (M8, code part): `DARU_CLICKHOUSE_ADMIN_USER`
  runs migrations and retention partition drops; the app user runs
  everything else. User written searches also run with `readonly=2`.
  `deploy/clickhouse-users.sql` for existing installs, and
  `deploy/clickhouse-init/10-daru-users.sh` creates `daru_app` in compose
  (password passed as a SHA-256 hash, never spliced into SQL). Live
  findings: lightweight DELETE needs `ALTER UPDATE` as well as `ALTER DELETE`
  on ClickHouse 25.x, so the app user has both; `ALTER DELETE` also permits
  `DROP PARTITION`, so the app user can delete data but cannot create,
  alter, or drop tables, or read files. `scripts/check-clickhouse-privileges.sh`
  checks this in CI.
- `/ready` and `/metrics`: `/ready` is 200 only when ClickHouse answers in
  2s; `/metrics` is Prometheus text (requests by route and status class,
  ingest accepted and rate limited, searches and errors, scans, quota
  rejections, login failures, running scans, readiness, uptime, goroutines,
  heap). `/metrics` is loopback only unless `DARU_METRICS_TOKEN` is set.
- Global ingest rate limiter and per user quotas: token bucket in events per
  second over all tokens (`DARU_INGEST_MAX_EPS`, default 50000, HEC code 9
  and Retry-After on refusal); per user running scans (2), scans per hour
  (30), and scheduled scans owned (20), all configurable. Scheduled scans
  are charged to the schedule's creator. A refused scan no longer leaves a
  "running" scan record behind (quota and slot are taken before the record
  is created).
- Webhook HMAC signing: `DARU_WEBHOOK_SECRET` adds `X-Daru-Timestamp` and
  `X-Daru-Signature: sha256=HMAC(secret, timestamp + "." + body)`, signed per
  attempt. `alerts.VerifyWebhook` and a Python snippet in the README show
  verification with a five minute replay window.
- SSO: OIDC single sign on, standard library only (authorization code flow,
  PKCE S256, state bound to an HttpOnly cookie, nonce). ID tokens verified
  locally: RS256 or ES256 only (`none` and HMAC refused), issuer, audience,
  azp, exp, iat, nonce; JWKS refetched on unknown kid at most once a minute;
  RSA keys under 2048 bits refused. Email must be verified when used, with an
  optional domain allowlist. Auto create is off by default; when on, new
  accounts get role `user` and no index access. Verified live against Dex:
  an allowed user signs in and is created least privileged, a disallowed
  domain is refused. SAML and LDAP are deliberately not native: hand written
  XML signature verification is a classic source of auth bypasses, and LDAP
  needs a third party client. Keycloak or Authentik federate both to OIDC.
- Alert count for multi-group stats: the measure column (`count` if present,
  else the first column that is numeric in every row) is summed over every
  group, with a full re-run when the 5 row sample was truncated. Timecharts
  sum every series. Number parsing is strict, so a host such as `10.0.0.1`
  is never read as 10 (the old `fmt.Sscan` path would have).
- Retention independent of the alert scheduler: `Store.RunRetention` runs at
  start and every 6 hours from `serve`. Live testing found an existing bug:
  ClickHouse's LEFT JOIN reports 1970-01-01 as the oldest event of an empty
  index, so every sweep issued 366 no-op ALTERs per empty index and logged
  them as drops (1098 on a fresh install). Empty indexes are now skipped.
  The events table TTL, which used to be a fixed 90 days and silently capped
  every index at 90, is now a 3650 day backstop (new installs and a metadata
  only `MODIFY TTL ... materialize_ttl_after_modify = 0` on upgrade, checked
  live: no mutation, data kept). Index retention is capped at 3650 days.
- Live checks that were impossible before, now done:
  - store integration tests pass against ClickHouse 25.8 (`DARU_TEST_CH`), and
    CI now runs them in an `integration` job with a ClickHouse service;
  - `docker build` succeeds (21.9 MB image); `docker compose up` with the
    new split users comes up, `/ready` is 200, the container goes healthy,
    and compose fails fast when `CLICKHOUSE_APP_PASSWORD` is unset;
  - 360px check in headless Chromium on every signed-in page: no page level
    horizontal scroll. Two layout bugs found and fixed: the search query box
    was squeezed to about 30px on phones, and the menu button showed on the
    login screen.
  - rex breakout (H5) against live ClickHouse: quote and paren payloads stay
    inside the regex literal (re2 rejects them as patterns), and a valid
    regex containing a quote runs as data. No breakout.

Gates for this pass: `gofmt -l .` empty, `go vet ./...` exit 0,
`go test -race ./... -count=1` all pass (187 top level tests, up from 162),
`node --check app.js` pass, `bash -n` on the new scripts pass.

## Branding

- Logo replaced with "Daru Tech Analytics Logo.png". The source art is white
  on transparent, so it is placed on a black tile to stay legible in the
  light theme. Generated: `logo-full.png` (login), `logo-mark.png` (sidebar,
  apple-touch-icon), `favicon.ico` (32 and 64 px); the original is kept at
  `docs/daru-logo.png` and used in the README. The old `logo.svg`,
  `docs/banner.png`, and `docs/banner.svg` were removed.

## Follow up, 2026-11-13 (2): native LDAP and SAML

The owner chose native LDAP and SAML over an OIDC bridge, and relaxed the
dependency rule in CONTRIBUTING.md to allow `github.com/go-ldap/ldap/v3`
v3.4.15 and `github.com/crewjam/saml` v0.6.3.

- Account sign in method: `users.auth_source` (local, ldap, oidc, saml;
  existing rows are local). An external identity signs in only to an
  account of its own method; a local password never signs in to an external
  account. Verified live: a directory user `bob` cannot open the local admin
  `bob`. This also tightened OIDC, which previously mapped onto any account
  with a matching username.
- LDAP: service bind, escaped search, exactly one match, user bind. TLS
  required (plain only to loopback with an explicit flag). Empty passwords
  refused before any network call (unauthenticated bind). Group DNs map to
  roles and resync at each sign in. Daru TOTP applies. Verified against a
  live glauth directory: correct passwords pass with group roles; wrong
  passwords, `*`, `al*`, and `alice)(uid=*` are refused; through the live
  server, auto create made `alice` an ldap admin.
- SAML: crewjam/saml service provider; signed responses required, SHA-1
  refused, replay cache, IdP initiated refused, request bound to the browser
  by a SameSite=None Secure cookie, AuthnRequests signed (RSA-SHA256 or
  ECDSA-SHA256) unless `DARU_SAML_UNSIGNED_REQUESTS=true`. End to end tests
  against crewjam's samlidp IdP with real keys: sign in and role sync work;
  a replayed response, an altered response, an ACS post without the state
  cookie, and a SAML identity matching a local account are all refused.
  Signed requests: the samlidp IdP verifies Daru's RSA-SHA256 signed
  HTTP-Redirect AuthnRequest against Daru's SP metadata and refuses it once
  the signature is corrupted. (samlidp's own login form then re-posts the
  request unsigned, so the full browser login test runs with signing off.)
- Admin UI: Users shows the sign in method; Add user picks it (password only
  for local accounts). Login page shows Sign in with SAML when configured.
- Gates: `gofmt -l .` empty, `go vet ./...` exit 0, `go test -race ./...`
  all pass (194 top level tests), `docker build` succeeds with the new
  modules.
- Not done here: govulncheck over the new modules. Running it was blocked
  twice by this session's permission settings (it downloads the tool); run
  `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` (CI already does).

## Follow up, 2026-11-13 (3): several Daru servers on one ClickHouse

- OIDC and SAML sign in state moved to a `sso_states` table, so a sign in
  started on one server can finish on another, and stays single use.
- SAML replay protection: an in-memory cache in front of a shared
  `used_ids` table, so an assertion accepted by any server is refused by all.
- Scan quotas are counted from the `scans` table every server writes
  (running in the last 30 minutes, started in the last hour, scheduled scans
  charged to their creator). If the counts cannot be read the scan is
  refused, so an outage cannot lift the quotas.
- Ingest limit: `DARU_INGEST_MAX_EPS` is for the whole deployment; with
  `DARU_REPLICAS=n` each server enforces its 1/n share.
- Verified: unit tests for two servers sharing state, and
  `TestSharedStateLive` against ClickHouse 25.8 (now also in CI).
- Trade-off, by design: ClickHouse has no transactions, so "take" and
  "consume" are a read then a write. Two servers racing on the very same
  state within milliseconds could both succeed. Each state is also bound to
  one browser cookie, and each server checks its own memory first. The
  index ACL cache stays per server with a 30 second lifetime, so an ACL
  change made on one server reaches the others within 30 seconds.

## Remaining honest limits

- govulncheck over the new modules has not been run in this session (the
  session's permissions blocked downloading it). CI runs it on every push;
  locally: `go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...`.
- install.sh Go SHA-256 pins are for Go 1.27.3 (re-verified against the
  go.dev download in this pass). If Go releases a patch, update the pins in
  install.sh and install.ps1 together.
