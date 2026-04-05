# ARTF — Hardcoded Artifacts

**Applies to:** Source and binary.

## Description

The presence of hardcoded values embedded directly in code or binary data that suggest external communication targets, stolen credentials, or operational infrastructure. Legitimate software occasionally hardcodes configuration, but the *type* and *context* of what is hardcoded matters enormously. A hardcoded localhost address is mundane. A hardcoded IP address in a package dependency with no documented infrastructure is not.

## Subtypes

| Subtype ID | Name | Description |
|---|---|---|
| `ARTF.IP` | IP Address | Raw IPv4 or IPv6 addresses. Especially suspicious when pointing to non-RFC1918 addresses in libraries that have no documented network functionality. |
| `ARTF.URL` | URL / URI | Hardcoded HTTP(S), FTP, or other protocol URLs. Suspicious when the target domain is unusual, recently registered, or unrelated to the package's stated purpose. |
| `ARTF.EMAIL` | Email Address | Embedded email addresses. May indicate exfiltration targets or C2 communication channels (email-based C2 is old but persistent). |
| `ARTF.CRYPTO_ADDR` | Cryptocurrency Address | Bitcoin, Ethereum, Monero, or other wallet addresses. In non-cryptocurrency software, this almost always indicates mining, ransomware, or theft. |
| `ARTF.CREDENTIAL` | Embedded Credential | API keys, tokens, passwords, private keys, AWS access keys, or other authentication material hardcoded in source or binary. May indicate backdoor access or accidental exposure. |
| `ARTF.HASH` | Cryptographic Hash | Hardcoded MD5, SHA-1, SHA-256, or other hashes. May indicate integrity checks against specific known artifacts, allowlisting/blocklisting, or anti-tamper mechanisms. |
| `ARTF.PATH` | Filesystem Path | Hardcoded absolute paths to sensitive locations (e.g., `/etc/shadow`, `~/.ssh/`, browser profile directories, cloud credential paths). Indicates targeted access. |
| `ARTF.CMD` | Shell Command String | Complete or partial shell commands embedded as strings. Strongly suspicious when constructed from fragments or encoded. |
| `ARTF.DOMAIN` | Domain Name | Hardcoded domain names, especially when they do not match the package's documented purpose, are recently registered, or use suspicious TLDs. |
| `ARTF.TIMESTAMP` | Hardcoded Date/Time | Specific timestamps embedded in code. May indicate time-bomb activation dates or campaign identifiers. |

## Severity Baseline

Varies significantly by subtype and context. `ARTF.CREDENTIAL` is high in isolation; `ARTF.URL` depends entirely on context.
