# Contributing to Daru

Thanks for your interest in improving Daru. This guide covers building, testing,
and submitting changes.

## Getting set up

You need Go 1.25+ and a reachable ClickHouse (Docker is the easy path).

```bash
git clone https://github.com/TYFSADIK/daru
cd daru
make run        # starts ClickHouse via Docker and runs daru
```

Or wire it up by hand:

```bash
go build -o daru ./cmd/daru
export DARU_CLICKHOUSE_URL=http://localhost:8123
./daru serve
```

## Before you open a pull request

Run the same checks CI runs:

```bash
make fmt        # gofmt -w .
make vet        # go vet ./...
make test       # go test ./...
```

CI will reject a branch that is not gofmt-clean or that fails `go vet` or the
tests, so run these locally first.

## Guidelines

- Keep the single-binary, no-extra-dependency design. The only runtime
  dependency outside the standard library and `golang.org/x/crypto` is
  ClickHouse over its HTTP interface. New third-party Go modules need a good
  reason.
- Add tests for new behavior. The query compiler, ingest field extraction, the
  cron parser, and the recon scope guard all have table-driven tests to follow.
- Match the style of the surrounding code: clear names, small functions, and
  comments that explain why rather than what.
- All generated SQL must go through the existing escaping helpers. Never build a
  query by concatenating untrusted input.

## Recon and security tooling

Daru drives dual-use security tools, and contributions in this area get extra
scrutiny:

- Every scan must stay behind the authorization gate (an authorization
  reference plus an explicit confirmation) and the scope guard.
- Daru does not ship denial-of-service tools, mass auto-exploiters, or
  anti-virus evasion tooling, and pull requests adding them will not be merged.

## Reporting bugs and ideas

Open an issue with steps to reproduce, what you expected, and what happened. For
security issues, follow [SECURITY.md](SECURITY.md) instead of opening a public
issue.
