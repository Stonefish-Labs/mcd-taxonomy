# BP-CREDTHEFT — Credential Theft

## Description

Code that locates, reads, and exfiltrates authentication material from the system. This is the most common objective of supply chain attacks: the attacker wants your AWS keys, SSH keys, browser passwords, or API tokens. The pattern is: find credentials, collect them, send them out.

## Constituent POIs

| Role | POI | Notes |
|---|---|---|
| **Required** | `CRED.*` or `FSYS.SENSITIVE` | Access to credential stores, sensitive paths, or environment secrets |
| **Required** | `NETW.*` | An exfiltration channel for the stolen credentials |
| Supporting | `OBFS.*` | Concealing what credentials are being targeted |
| Supporting | `RECN.OS` or `RECN.USER` | Profiling the system to locate platform-specific credential stores |
| Supporting | `FSYS.ARCHIVE` | Packaging multiple credential files for exfiltration |
| Supporting | `ARTF.PATH` | Hardcoded paths to known credential locations |

## Real-World Analogue

The `Telnyx` PyPI attack (2026), numerous npm attacks targeting `.npmrc` tokens and `.env` files. Attacker reads `~/.aws/credentials`, `~/.ssh/id_rsa`, browser SQLite databases, and sends them to a remote endpoint.

## Investigation Guidance

- **Verify:** What specific files or credential stores are accessed? Where does the data go?
- **Escalates:** Multiple credential stores targeted. Data is encrypted or encoded before transmission. Exfiltration target is an IP address or recently registered domain. Activity is triggered at install time.
- **De-escalates:** Package is a documented credential management tool. Access is to the package's own configuration files. No network transmission of credential data.
