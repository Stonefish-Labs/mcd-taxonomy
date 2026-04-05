# BP-TROJAN — Trojan / Disguised Payload

## Description

Code that presents a legitimate, useful interface while concealing malicious functionality. The trojan pattern is about *disguise*: the package does what it claims to do, but it also does something the user did not request. This is harder to detect than a pure payload because the legitimate functionality provides cover.

## Constituent POIs

| Role | POI | Notes |
|---|---|---|
| **Required** | *Any malicious payload POI combination* | The hidden malicious behavior |
| **Required** | `OBFS.*` or *structural concealment* | The malicious behavior is concealed within or alongside legitimate code |
| Supporting | `EVSN.ENVCHECK` | Activating only in specific environments (production, not test) |
| Supporting | `TIME.CMP` | Delaying activation to pass initial review |
| Supporting | `LOAD.EVAL` or `LOAD.IMPORT` | Dynamic loading of the malicious component |

## Real-World Analogue

The `event-stream` attack (2018) — a legitimate, widely-used package was modified to include a targeted payload that only activated for a specific Bitcoin wallet application. The XZ Utils backdoor (2024) — years of legitimate contribution to build trust before introducing the backdoor.

## Investigation Guidance

- **Verify:** Does the package do what it claims? What additional behaviors exist beyond the documented functionality? Is the malicious component loaded conditionally?
- **Escalates:** Hidden functionality targets specific victims or environments. Malicious code was introduced in a recent update by a relatively new contributor. Concealment is sophisticated (not just messy code).
- **De-escalates:** All code is consistent with the package's documented purpose. No concealment mechanisms detected.
