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

## Escalation Factors

The following conditions increase the suspicion level of any `ARTF` finding:

**Context-agnostic escalators** — apply regardless of subtype:

- **The artifact is found inside encoded or obfuscated content.** Decode first, then apply ARTF classification. The combination of `OBFS.*` + `ARTF.*` is materially more suspicious than either alone — the encoding exists to hide the artifact from static analysis.
- **Multiple ARTF subtypes are present in the same file or package.** Legitimate packages rarely have reason to hardcode an IP address, a filesystem path, and a shell command string simultaneously. Clustering of artifact types suggests operational infrastructure.
- **The artifact appears in a dependency with no documented network, credential, or system-access functionality.** A utility library, parser, or formatter has no reason to contain hardcoded URLs, paths to credential files, or shell commands.
- **The artifact was introduced in a recent version but absent from prior versions.** Diff the current version against prior releases. Newly introduced artifacts in a maintenance update are a high-confidence signal of compromise.
- **The artifact is constructed rather than declared.** Assembled from string fragments, environment variables, or computed values rather than appearing as a literal. Construction indicates intent to defeat static string extraction.
- **The artifact is not referenced by the package's public API or visible execution paths.** Dead-code artifacts with no apparent legitimate use are high suspicion.

**Subtype-specific escalators:**

- **`ARTF.IP`:** Non-RFC1918 address in a library with no documented network functionality. Address resolves to a VPS, bulletproof host, or residential IP block. Address appears in multiple suspicious packages.
- **`ARTF.URL`:** Target domain is recently registered (under 90 days), uses a suspicious TLD, or has no public web presence. URL path structure resembles C2 patterns (`/gate.php`, `/panel`, `/connect`). URL points to a raw IP rather than a named domain.
- **`ARTF.EMAIL`:** Email is from a free provider in code with no user-facing contact functionality. Domain portion matches no known project infrastructure.
- **`ARTF.CRYPTO_ADDR`:** Any occurrence in software that is not explicitly a cryptocurrency wallet, exchange, or donation handler. Monero addresses in particular — Monero's privacy properties make it the dominant choice for criminal infrastructure.
- **`ARTF.CREDENTIAL`:** Any occurrence regardless of context is high severity. Escalate further if the credential format matches a known provider (AWS `AKIA` prefix, GitHub `ghp_`, Slack `xoxb-`). Credentials in binary artifacts may indicate stolen keys.
- **`ARTF.HASH`:** Hash is used in a comparison against a runtime-computed value of a sensitive resource (file, process, network response). Weak algorithm (MD5, SHA-1) in a security-relevant context suggests legacy or adversarial design.
- **`ARTF.PATH`:** Path targets credential files (`~/.aws/credentials`, `~/.ssh/id_rsa`, `/etc/shadow`), browser profile directories, cloud metadata endpoints (`169.254.169.254`), or keychain locations. Path is OS-specific in a cross-platform package, suggesting targeted payload.
- **`ARTF.CMD`:** Command is destructive, exfiltrating, or persistence-establishing (`curl | bash`, `crontab`, `chmod +x`, `rm -rf`). Command is fragmented across multiple strings assembled at runtime.
- **`ARTF.DOMAIN`:** Domain has no relationship to the package name, author, or stated purpose. Domain uses a lookalike pattern mimicking a legitimate CDN or update service.
- **`ARTF.TIMESTAMP`:** Timestamp is in the future relative to the package publication date. Timestamp appears alongside conditional execution logic (`TIME.CMP`). Multiple timestamps present, suggesting a campaign schedule.

## De-escalation Factors

The following conditions reduce — but do not eliminate — suspicion:

- **The artifact matches the package's documented infrastructure.** A URL in an SDK pointing to the vendor's known API domain, where that domain is referenced in the README and matches the vendor's certificate, is expected behavior. Verify independently — do not trust inline comments.
- **The artifact is present in test fixtures or files explicitly named as test resources.** Hardcoded IPs, credentials, and commands in test files are common. Verify the test code is not executed in production paths and that the test artifacts are clearly marked as non-operational.
- **The artifact is a well-known public constant.** RFC-specified addresses (e.g., `8.8.8.8` as a documented DNS example), example credentials in documentation templates (`YOUR_API_KEY_HERE`), and standard hash values for known files are not indicators in isolation.
- **The artifact has been present across many versions with no behavioral change.** Long-lived, visible, unchanged artifacts are less suspicious than recently introduced ones. However, this does not apply to `ARTF.CREDENTIAL` — a long-lived embedded credential is still a credential exposure regardless of history.

> **Important caveat:** De-escalation based on documentation or public infrastructure claims requires independent verification. The Axios compromise embedded C2 URLs into a package that had legitimate documented URLs elsewhere. An attacker who understands a target package's infrastructure can craft artifacts that appear to belong.

## Common Combinations

| Combination | Suggests | Escalation |
|---|---|---|
| `ARTF.URL` or `ARTF.IP` + `NETW.*` | Hardcoded network target with runtime communication to that target | High — the artifact names the destination; the NETW call acts on it |
| `ARTF.PATH` + `CRED.*` | Sensitive path hardcoded, credential access at runtime | High — ARTF.PATH identifies the target; CRED classifies the access behavior |
| `ARTF.PATH` + `FSYS.*` | Hardcoded path with filesystem access | Medium-high — severity depends on the path target and the operation |
| `ARTF.CMD` + `EXEC.CMDCON` | Shell command string present, command construction at runtime | High — ARTF.CMD is the artifact; EXEC.CMDCON is the construction behavior |
| `ARTF.TIMESTAMP` + `TIME.CMP` | Future timestamp hardcoded, runtime comparison gates execution | High — the classic time bomb pattern; neither is conclusive alone |
| `ARTF.CREDENTIAL` + `PRST.*` | Embedded credential alongside persistence mechanism | High — suggests stolen credential used to establish durable access |
| `ARTF.IP` or `ARTF.DOMAIN` + `OBFS.*` | Network artifact found inside encoded or obfuscated content | High — encoding is designed to defeat static analysis of the target |
| `ARTF.CRYPTO_ADDR` + `RSRC.*` | Cryptocurrency address alongside resource consumption | High — cryptojacking pattern: wallet address + compute usage |
| `ARTF.HASH` + `EVSN.TAMPER` | Hardcoded hash used in integrity verification | Medium — may indicate anti-tamper or anti-analysis; investigate what is being verified |
| `ARTF.EMAIL` + `NETW.EMAIL` | Email address alongside SMTP or email API usage | High — email may be the exfiltration target |

## Disambiguation

### ARTF.PATH vs. CRED

`ARTF.PATH` describes the artifact — a hardcoded string that is a filesystem path. `CRED` describes behavior — code that reads, steals, or transmits credential material. When a hardcoded path points to a known credential location (`~/.aws/credentials`, `~/.ssh/`, browser profile directories), classify both: `ARTF.PATH` for the artifact and the appropriate `CRED.*` subtype if and when that path is actually read at runtime. The presence of the path alone is sufficient to raise `ARTF.PATH`; observed or inferred credential access is required to raise `CRED`.

### ARTF.CMD vs. EXEC.CMDCON

`ARTF.CMD` is raised when a complete or partial shell command appears as a hardcoded string literal. `EXEC.CMDCON` is raised when command strings are assembled at runtime from fragments, variables, or computed values. These frequently co-occur. When both are present, raise both. `ARTF.CMD` in isolation (a complete, static, visible command string) is still suspicious but is more likely to be caught by naive scanning. `EXEC.CMDCON` with no static `ARTF.CMD` signal suggests an attempt to evade static analysis.

### ARTF.URL vs. ARTF.DOMAIN vs. ARTF.IP

These three subtypes represent different specificity levels of network targeting. `ARTF.IP` is a raw address with no name resolution required. `ARTF.DOMAIN` is a hostname requiring DNS resolution. `ARTF.URL` is a fully-qualified resource locator including path. Raise all applicable subtypes — a URL contains a domain which may resolve to an IP; each carries distinct analytic value.

### ARTF.CREDENTIAL vs. ARTF.HASH

Both involve encoded values that may look similar. The distinction is purpose: `ARTF.CREDENTIAL` is authentication or authorization material (API keys follow provider-specific formats, passwords appear in auth contexts, private keys have PEM headers). `ARTF.HASH` is a fixed-length digest value used for comparison or verification. When uncertain, investigate the usage context — how the value is used determines which classification applies.

### ARTF vs. Dynamic Construction

ARTF covers values directly recoverable from static analysis — the artifact is present and classifiable without executing the code. When an artifact only materializes at runtime through computation, the primary classification shifts to the construction or obfuscation POI (`OBFS.*`, `EXEC.CMDCON`). However, if decoding or static analysis of obfuscated content reveals an ARTF-classifiable value, raise both: the `OBFS` for the encoding behavior and the appropriate ARTF subtype for the recovered artifact.

## Investigation Questions

When an `ARTF` finding is detected, answer these questions to drive the investigation:

### Triage and scoping:
1. **Which ARTF subtypes are present?** Document each artifact, its type, its location in the codebase, and the version in which it first appeared.
2. **Was the artifact introduced in a recent version?** If so, which version, and was the change authored by a known maintainer?
3. **Is the artifact reachable from any execution path?** Install scripts, import-time code, exported functions, CLI entrypoints? Dead-code artifacts are lower risk but not no risk.
4. **Is the artifact inside encoded or obfuscated content?** If so, decode it first, then re-evaluate.

### Per-subtype investigation questions:
5. **`ARTF.IP`** — Does this IP resolve to known infrastructure for the package author? Does it appear on threat intelligence feeds or in other suspicious packages?
6. **`ARTF.URL`** — When was the target domain registered? Does it have a public web presence? Does the URL path structure resemble known C2 patterns?
7. **`ARTF.EMAIL`** — Is this email associated with the project author's known identity? Is there any code path that would transmit data to this address?
8. **`ARTF.CRYPTO_ADDR`** — Is this package explicitly cryptocurrency-related? If not, is there any plausible legitimate explanation? What blockchain and address type?
9. **`ARTF.CREDENTIAL`** — What provider or format does this credential match? Is the credential still valid? Does it appear in other packages or repositories?
10. **`ARTF.HASH`** — What algorithm is used? What value is being hashed at runtime for comparison? What is the significance of detecting that specific file or resource?
11. **`ARTF.PATH`** — Does this path point to credential material, browser data, SSH keys, or cloud credential files? Is the path actually accessed at runtime?
12. **`ARTF.CMD`** — Is the command complete or partial? What does execution accomplish? Would it require elevated privileges?
13. **`ARTF.DOMAIN`** — What is the domain's registration date and registrar? Does it appear in passive DNS for known malicious infrastructure? Does the name mimic a legitimate service?
14. **`ARTF.TIMESTAMP`** — Is the timestamp in the future relative to publication date? Is it referenced in conditional logic? Are multiple timestamps present, suggesting a schedule?

### Cross-cutting:
15. **Do the artifacts cluster?** Multiple subtypes in the same file, or artifacts that together describe a complete attack operation (a URL for C2 check-in, a path for credential access, a command for execution), are materially more suspicious than isolated findings.
