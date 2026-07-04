# Security Policy

cordon is a PII/PHI/PCI compliance gateway — it sits between your app and the model provider so raw sensitive values never leave your perimeter. Vulnerability reports get priority attention.

## Reporting a vulnerability

Please **do not open a public issue** for security reports.

- **Preferred:** [GitHub private vulnerability reporting](https://github.com/askalf/cordon/security/advisories/new) — creates a private advisory visible only to maintainers.
- **Email:** support@askalf.org with `cordon security` in the subject.

You'll get an acknowledgement within 72 hours. Please include a minimal reproduction where possible.

## Supported versions

cordon is pre-1.0: only the latest release receives security fixes; there are no maintenance branches.

## In scope

Anything that breaks the core promise — de-identified data out, fail-closed on error:

- A detector bypass: PII/PHI/PCI/secret patterns cordon claims to cover reaching the upstream provider unredacted
- A fail-closed violation: a request forwarded upstream after a detection error instead of being blocked
- The reversible-mode vault leaking real values anywhere other than the restored client response
- Audit-log tampering, or raw values appearing in the audit log (it must record counts/types only)
