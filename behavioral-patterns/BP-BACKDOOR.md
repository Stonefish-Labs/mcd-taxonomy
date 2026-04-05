# BP-BACKDOOR — Backdoor

## Description

Any mechanism that provides unauthorized access to a system by bypassing normal authentication or authorization controls. Backdoors come in two fundamentally different forms that share the same risk profile but have very different POI signatures:

**Variant A — Remote Access Backdoor:** Code that provides persistent remote command execution. A C2 listener, a reverse shell, a polling loop that fetches and executes instructions from an attacker-controlled server. This is the classic "implant" — sophisticated, purpose-built for ongoing access, typically introduced by an external attacker through a supply chain compromise or exploitation.

**Variant B — Authentication Bypass:** Hardcoded credentials, hidden accounts, magic tokens, debug endpoints, or logic that short-circuits authentication checks. These are often introduced by insiders — a developer who wants a quick way in from home, a "temporary" debug account that was never removed, a vendor support backdoor baked into a product. The intent may not be malicious, but the *risk* is identical: anyone who discovers the bypass owns the system. These are layer-8 problems with layer-1 consequences. Authentication bypasses are among the most common findings in code audits and penetration tests, and among the easiest to exploit because they require no tooling — just knowledge of the secret.

Both variants provide unauthorized access. Both should trigger investigation. The distinction matters for understanding intent and remediation, not for determining whether something is a finding.

## Constituent POIs — Variant A (Remote Access)

| Role | POI | Notes |
|---|---|---|
| **Required** | `NETW.LISTEN` or `NETW.HTTP` (polling) | The backdoor must receive instructions — either by listening or by periodically checking in |
| **Required** | `EXEC.SHELL` or `EXEC.PROC` | The ability to execute received commands |
| Supporting | `PRST.*` | Persistence to survive reboots |
| Supporting | `OBFS.*` | Concealing the backdoor logic |
| Supporting | `EVSN.*` | Evading detection while running |
| Supporting | `CRPT.SYMENC` | Encrypted command channel |
| Supporting | `ARTF.IP` or `ARTF.DOMAIN` | Hardcoded C2 infrastructure |
| Supporting | `NETW.DECENTRAL` | Takedown-resistant C2 channel |

## Constituent POIs — Variant B (Authentication Bypass)

| Role | POI | Notes |
|---|---|---|
| **Required** | `ARTF.CREDENTIAL` | Hardcoded password, token, API key, or cryptographic key that grants access |
| Supporting | `ARTF.HASH` | Hardcoded hash that a known password is compared against |
| Supporting | `OBFS.ENCODE` or `OBFS.ENCRYPT` | Encoded or encrypted credentials (base64'd password, XOR'd token) — obfuscation suggests awareness that the bypass shouldn't be there |
| Supporting | `OBFS.STRCON` | Credential assembled from fragments to avoid string detection |
| Supporting | `EVSN.ENVCHECK` | Bypass activates only in specific environments (e.g., from specific IP ranges, on specific hostnames) |
| Supporting | `NETW.LISTEN` | Hidden administrative endpoint or undocumented API route |

## Real-World Analogue

**Variant A:** The SolarWinds SUNBURST backdoor (2020). The XZ Utils backdoor (2024). Classic reverse shells in compromised packages. The LiteLLM sysmon.service persistence daemon polling checkmarx[.]zone for payloads.

**Variant B:** The Juniper ScreenOS backdoor (2015) — a hardcoded password (`<<< %s(un='%s') = %u`) allowed anyone who knew it to gain admin access to any Juniper firewall. Countless "admin/admin" default credentials in IoT devices. Debug endpoints left in production (`/debug/exec`, `/_internal/admin`). The `if user == "support" and password == "sup0rt!"` pattern found regularly in code audits of enterprise software.

## Investigation Guidance

- **Verify (Variant A):** What is the network communication pattern? Is it listening or polling? What is the C2 target? What commands can be executed?
- **Verify (Variant B):** What does the hardcoded credential grant access to? Is this a known default credential or something custom? Is the bypass conditional on environment or always active? Is this in authentication/authorization code paths?
- **Escalates:** Persistence mechanisms installed. Communication is encrypted. C2 target is obfuscated or dynamically resolved. Hardcoded credential grants administrative or root-level access. Bypass is obfuscated or hidden in unexpected code locations. Multiple bypass mechanisms exist (suggests deliberate planting, not laziness).
- **De-escalates (Variant A):** Network listener is a documented feature (e.g., a web framework's development server). No command execution capability attached to the listener.
- **De-escalates (Variant B):** Credential is in a test file, example configuration, or documentation. Credential is a well-known default that is expected to be changed on deployment. The authentication code is part of a development/staging configuration clearly not intended for production.
