# Security Policy

## Reporting a vulnerability

Please do not open a public issue for security vulnerabilities.

Instead, report them privately through GitHub's
[security advisories](https://github.com/TYFSADIK/daru/security/advisories/new)
for this repository. Include:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- the affected version or commit.

You can expect an initial response within a few days. Once a fix is ready, we
will coordinate disclosure.

## Scope

Daru is a self-hosted security tool that can drive scanners against hosts you
specify. The following are expected behavior, not vulnerabilities:

- Running an authorized scan against a target you have confirmed you are
  permitted to test.
- A user with the `admin` role being able to manage users and tokens.

Reports we are interested in include authentication or session bypass, query
or command injection, privilege escalation between roles, bypass of the recon
authorization gate or scope guard, and leakage of secrets.

## Responsible use

Daru's recon features are for authorized testing of systems you own or have
explicit permission to test. You are responsible for how you use them.
