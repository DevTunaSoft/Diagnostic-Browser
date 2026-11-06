# Diagnostic Browser

A Windows diagnostic browser project focused on safe, privacy-conscious troubleshooting, incident capture, local analysis, and recovery.

## Status

**Under active development — not production-ready.** A self-contained Windows executable, embedded browser, integrated desktop interface, and full Windows acceptance tests are release requirements, not yet verified deliverables.

## Principles

- Vendor-neutral branding and implementation interfaces.
- Never commit credentials, tokens, user records, diagnostic evidence, or proprietary configurations.
- No collection of request bodies, cookies, authentication material, or private page content.
- All end-user runtime dependencies must ship inside one Windows executable; no first-run downloads.
- Automated tests and Windows packaging must pass before a release is published.
- Browser security policies must be respected.

## Publication policy

No production release until native Windows tests, offline model integrity, encryption, browser recovery, and the integrated UI have been verified. Contributions should not include customer-specific names, addresses, domains, or configurations.
