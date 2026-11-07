# Daru

Daru is a self-hosted log analytics and SIEM platform. It collects logs, stores
them in ClickHouse, and lets you search them with a piped query language, build
dashboards, run scheduled alerts, and triage security events. It runs entirely
on your own machines. There are no API keys and no external services.

One Go binary holds the search API, the ingest endpoints, the alert scheduler,
and the web interface. The only other piece is ClickHouse, which does the
storage and the heavy lifting of search.

## What it does

- **Collect** logs over HTTP in the Splunk HEC format (so forwarders already set
  up for HEC can point at Daru unchanged), as raw text, or as JSON. Fields are
  pulled out automatically from `key=value` pairs and JSON.
- **Search** with a pipe language: `search`, `where`, `eval`, `stats`,
  `timechart`, `chart`, `top`, `rare`, `rex`, `spath`, `sort`, `dedup`,
  `rename`, `bin`, `fillnull`, `eventstats`, `streamstats`, and more.
- **Visualize** results as tables, time charts, and bar charts, with a field
  sidebar for quick drill-down.
- **Dashboards** of saved panels.
- **Alerts**: scheduled searches on a cron schedule, with a condition and
  severity. A firing can open a notable event.
- **Security**: a notable-event queue for incident triage, with status and
  owner.
- **Accounts**: built-in users with Argon2id password hashing, roles (admin,
  power, user), and revocable sessions. No external identity provider needed.
- **Retention**: per-index retention in days, enforced by ClickHouse TTL.
- **Recon**: run authorized security tools (nmap, masscan, nuclei, subfinder,
  amass, tshark, and more) and native collectors (crt.sh, DNS, TLS, RDAP) and
  pull their findings into search. Every scan is gated behind an authorization
  reference and a permission confirmation.
- **Network**: discover live devices on your LAN with IP, hostname, MAC,
  vendor, and OS.

## Install (one command)

Daru runs on Linux, macOS, Raspberry Pi, Windows, and Android (Termux).

**Linux, macOS, Raspberry Pi, Termux:**

```bash
git clone https://github.com/TYFSADIK/daru
cd daru
./install.sh
```

**Windows (PowerShell):**

```powershell
git clone https://github.com/TYFSADIK/daru
cd daru
powershell -ExecutionPolicy Bypass -File install.ps1
```

The installer builds Daru (installing a Go toolchain if you do not have one),
starts ClickHouse with Docker if it is available, generates admin and database
passwords into `~/.daru/daru.env`, and prints your login. Then:

```bash
set -a; . ~/.daru/daru.env; set +a
daru serve
```

Open http://localhost:8088 and sign in as the `admin` user printed by the
installer.

### Platform notes

- **Raspberry Pi**: use a 64-bit OS with 4 GB+ RAM; ClickHouse runs natively on
  arm64.
- **Android (Termux)**: the Daru binary runs, but ClickHouse does not run on
  Android. Point Daru at a ClickHouse on another machine with
  `DARU_CLICKHOUSE_URL=http://<host>:8123`.
- **No Docker?** Install ClickHouse natively (its official installer is
  `curl https://clickhouse.com/ | sh`), or point `DARU_CLICKHOUSE_URL` at an
  existing instance.

Optional security scanners for the recon features (nmap, masscan, nuclei, and
so on) are installed separately and only with your consent:

```bash
./scripts/install-recon-tools.sh
```

### Prebuilt binaries

Each release publishes static binaries for every platform (`make release`
builds them locally into `dist/`). Download the one for your system, drop it on
your `PATH`, and run `daru serve`.

## Run with Docker Compose

```bash
cd deploy
# Change the passwords first.
docker compose up -d
```

Open http://localhost:8088 and sign in with the admin account you set in
`DARU_ADMIN_USER` and `DARU_ADMIN_PASSWORD`.

Send some sample logs:

1. In the UI, go to **Admin > Ingest tokens** and create a token. Copy it.
2. Run the generator:

   ```bash
   python3 examples/sendlogs.py --server http://localhost:8088 --token YOUR_TOKEN --count 2000
   ```

3. Go to **Search** and try:

   ```
   * | timechart span=1h count by host
   status=500 | stats count by host
   * | top url
   sourcetype=api_json | stats avg(latency_ms) as avg_latency by user | sort -avg_latency
   ```

## Running without Docker

You need Go 1.25+ and a reachable ClickHouse.

```bash
go build -o daru ./cmd/daru
export DARU_CLICKHOUSE_URL=http://localhost:8123
export DARU_CLICKHOUSE_USER=default
export DARU_CLICKHOUSE_PASSWORD=yourpassword
./daru useradd -u admin -p 'a-strong-password' -role admin
./daru serve
```

## Sending logs

The HEC endpoint accepts the same JSON shape as Splunk's HTTP Event Collector:

```bash
curl http://localhost:8088/services/collector \
  -H "Authorization: Splunk YOUR_TOKEN" \
  -d '{"event":"user=alice action=login status=200","sourcetype":"app","host":"web01"}'
```

Raw lines (one event per line):

```bash
curl http://localhost:8088/services/collector/raw?sourcetype=syslog \
  -H "Authorization: Splunk YOUR_TOKEN" \
  --data-binary @/var/log/syslog
```

## Query language

A query is a series of commands joined by `|`. The first command is a search
over the raw text and extracted fields; later commands transform the results.

```
index=web status>=500 host=api*
  | eval slow = if(latency_ms > 500, "yes", "no")
  | stats count, avg(latency_ms) as avg_ms by host, slow
  | sort -count
```

Time ranges use forms like `-15m`, `-24h`, `-1d@d` (snap to the start of the
day), epoch seconds, or ISO timestamps.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `DARU_LISTEN` | `:8088` | Listen address |
| `DARU_CLICKHOUSE_URL` | `http://localhost:8123` | ClickHouse HTTP URL |
| `DARU_CLICKHOUSE_DB` | `daru` | Database name |
| `DARU_CLICKHOUSE_USER` | `default` | ClickHouse user |
| `DARU_CLICKHOUSE_PASSWORD` | | ClickHouse password |
| `DARU_ADMIN_USER` | | Bootstrap admin, created on first run |
| `DARU_ADMIN_PASSWORD` | | Bootstrap admin password |
| `DARU_SECURE_COOKIES` | | Set to `true` behind HTTPS |

## Architecture

```
  forwarders / apps                 browser
        │ HEC / raw / JSON             │ HTTPS
        ▼                              ▼
  ┌───────────────────────── daru (one binary) ──────────────────────────┐
  │  ingest  →  field extraction        search API  →  BQL parser          │
  │                     │                      │         → SQL compiler     │
  │  alert scheduler ───┼──────────────────────┤                           │
  │  web UI (embedded)  │                      │                           │
  └─────────────────────┼──────────────────────┼───────────────────────────┘
                        ▼                      ▼
                     ┌──────────────── ClickHouse ────────────────┐
                     │  events, users, sessions, saved searches,  │
                     │  dashboards, alerts, notable events        │
                     └────────────────────────────────────────────┘
```

## Status

Daru is under active development. Working today: ingest (HEC, raw, JSON), the
query language and compiler, the search UI with charts, saved searches,
dashboards, scheduled alerts, the notable-event queue, user and token
administration, and per-index retention.

## License

MIT. See [LICENSE](LICENSE).
