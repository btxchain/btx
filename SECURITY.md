# Security Policy

## Supported Versions

See our website for versions of BTX that are currently supported with
security updates: https://btx.dev/

## Reporting a Vulnerability

Report security issues privately, by either route:

- GitHub private vulnerability reporting: the "Report a vulnerability"
  button on the repository's Security tab
  (https://github.com/btxchain/btx/security/advisories/new). Only the
  maintainers see the report.
- Email the BTX Development Team at team@btx.dev (not for support).

If sensitive material is involved, ask the BTX Development Team for the current
disclosure key before sending secrets. Do not use inherited upstream keys for
BTX vulnerability reports.

Do not report a security issue in a public issue, pull request, discussion or
chat. That includes fuzzer crashes, sanitizer reports and crashing inputs that
reach consensus, validation, P2P, mempool or wallet code: a crashing input can
show an attacker how to crash running nodes until it is fixed. Open a pull
request for the fix only after the maintainers agree that it can be public.

A useful report gives the affected version or commit, what an attacker can do,
the steps or the input that reproduce it, and who else knows about it.
