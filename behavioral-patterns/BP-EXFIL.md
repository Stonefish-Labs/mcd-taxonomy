# BP-EXFIL — Data Exfiltration

## Description

Code that collects data from the local system and transmits it externally. Distinct from credential theft in scope: data exfiltration targets arbitrary valuable data — source code, databases, documents, configuration — not specifically authentication material.

## Constituent POIs

| Role | POI | Notes |
|---|---|---|
| **Required** | `FSYS.READ` or `FSYS.ENUM` or `CRED.*` or `RECN.PROCMEM` | Reading, discovering, or collecting target data from any source — files, credentials, environment, or process memory |
| **Required** | `NETW.*` | Transmitting the data externally — any network channel qualifies |
| Supporting | `ARTF.EMAIL` | A hardcoded email address paired with email-sending functionality (`NETW.EMAIL`) is one of the oldest and most direct exfiltration patterns |
| Supporting | `ARTF.URL` or `ARTF.IP` or `ARTF.DOMAIN` | Hardcoded exfiltration destination |
| Supporting | `NETW.WEBHOOK` | Exfiltration via messaging APIs (Discord webhooks, Telegram bots) |
| Supporting | `FSYS.ARCHIVE` | Bundling data for efficient exfiltration |
| Supporting | `OBFS.ENCODE` or `CRPT.SYMENC` | Encoding or encrypting data before transmission |
| Supporting | `NETW.DNS` | DNS tunneling for covert exfiltration |
| Supporting | `RECN.*` | Profiling the system to identify high-value targets |
| Supporting | `EVSN.*` | Rate-limiting or timing exfiltration to avoid detection |

## Real-World Analogue

Supply chain attacks that tar up the entire working directory and POST it to a hardcoded URL on an attacker-controlled server. The LiteLLM payload encrypting stolen data and POSTing it to `models[.]litellm[.]cloud`. Classic email-based exfil: read sensitive files, attach to an email, send to `attacker@freemail.com`. Corporate espionage tools that slowly exfiltrate documents via DNS tunneling. Discord webhook exfil: stolen tokens sent as messages to a hardcoded Discord webhook URL.

## Investigation Guidance

- **Verify:** What data is being read? Where is it being sent? Is the destination hardcoded? Who controls the destination? Does the destination domain/IP/email have any relationship to the project or organization?
- **Escalates:** Large volumes of data. Destination is a hardcoded IP address, a recently registered domain, a free email provider, or a personal messaging webhook. Access to source code repositories or databases. Exfiltration via covert channel (DNS, steganography). Data is encrypted before transmission. Destination domain does not match the package's stated purpose or organization.
- **De-escalates:** Data sent is standard telemetry or crash reporting. Destination is a well-known analytics service. Transmission is documented. Destination domain is clearly associated with the project's organization.
