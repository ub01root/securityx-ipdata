# Security Policy

Guard SecurityX - System Anti-VPN Global (securityx-ipdata + securityx-guard).

## Reporting a vulnerability

- Email: **security@securityx.sbs**
- Do not open a public issue for vulnerabilities.
- Include: affected file/endpoint, reproduction steps, and impact.

Please do not include real personal data in a report.

## Scope notes

- The blocklist data is generated automatically from public datasets. Reports
  of **false positives / false negatives** about a specific IP are not
  vulnerabilities; use the `/guard` dispute flow instead.
- "Upstream data broken / list empties" is an operational incident: it fails
  the daily run by design (regression guard) and never publishes a truncated
  list.

## Data integrity guarantees

- No pull request from external contributors is used to import blocklist
  data; data arrives only via the automated pipeline or the moderated
  community queue (see `GUARD-SECURITYX-PLAN.md`).
- `main` is expected to be protected (no force-pushes, no deletions,
  required reviews for changes outside the automated release flow).
- Releases are versioned tags with `manifest.json` and per-file checksums.
