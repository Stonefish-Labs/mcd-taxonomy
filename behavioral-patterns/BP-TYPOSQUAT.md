# BP-TYPOSQUAT — Typosquat / Dependency Confusion

## Description

A package that impersonates a legitimate package through name similarity, namespace confusion, or version manipulation. The package itself may contain any of the above behavioral patterns as its payload — typosquatting is a *delivery strategy*, not a payload type. Detection relies on package metadata analysis combined with analysis of the payload.

## Constituent POIs

| Role | POI | Notes |
|---|---|---|
| **Required** | `PKGM.PUBLISH` | Publication anomalies (name similarity to popular packages, new account, rapid publication) |
| **Required** | *Any payload pattern* | The typosquat package must deliver a payload |
| Supporting | `PKGM.DEPMANIP` | Dependency confusion indicators (internal package name on public registry) |
| Supporting | `OBFS.*` | Obfuscated payload |
| Supporting | `PKGM.INSTALL` | Install-time execution of the payload |

## Real-World Analogue

Thousands of typosquat packages on npm and PyPI annually. The `crossenv` attack (typosquat of `cross-env`). Internal package namespace attacks against major tech companies.

## Investigation Guidance

- **Verify:** What legitimate package does this resemble? How old is the publishing account? What does the payload do?
- **Escalates:** Package name is edit-distance-1 from a popular package. Publishing account is new. Package contains any of the above behavioral patterns.
- **De-escalates:** Package has a long publication history. Name similarity is coincidental with unrelated functionality. No malicious payload detected.
