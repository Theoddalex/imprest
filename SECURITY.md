# Security Policy

imprest guards money. Security reports are taken seriously and handled with
priority over all other work.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately via [GitHub Security Advisories](https://github.com/theoddalex/imprest/security/advisories/new)
("Report a vulnerability" on the repo's Security tab).

You can expect an acknowledgment within 72 hours. If the report is valid, a fix
is developed privately and credited to you in the release notes (unless you
prefer anonymity).

## Scope

Especially interested in:

- **Policy bypass** — any way an agent can spend outside its mandate
  (cap evasion, budget-window tricks, allowlist/denylist circumvention,
  approval-queue abuse)
- **Key exposure** — any path by which the guarded wallet key reaches an
  agent, a log, an error message, or the network
- **Identity spoofing** — an agent acting under another agent's (or an
  admin's) identity
- **Audit evasion** — spending that leaves no audit row, or mutation of
  existing audit rows
- **x402 fetch path** — SSRF, redirect tricks, payment-header leakage,
  settlement double-spend

## Out of scope

- Vulnerabilities in dependencies (report upstream; a heads-up here is still
  welcome so the pin can be bumped)
- Attacks requiring an already-compromised operator machine or filesystem
  access to `wallet.key` / `policy.yaml` (the OS is the trust boundary in
  stdio mode, as documented)
- The security of any LLM or agent framework calling the server

## Supported versions

Only the latest release receives security fixes.
