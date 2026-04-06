# CRED — Credential and Secret Access

**Applies to:** Source and binary.

## Description

Any operation that specifically targets authentication material, secrets, tokens, or keys stored on the system. This is distinguished from general filesystem access by *intent*: `CRED` POIs target locations and data formats that are known to contain authentication material. This is the objective of a large proportion of supply chain attacks — the attacker wants your credentials, API keys, or session tokens, not your code.

## Subtypes

| Subtype ID | Name | Description |
|---|---|---|
| `CRED.KEYCHAIN` | OS Credential Store Access | Accessing macOS Keychain, Windows Credential Manager, Linux keyrings (GNOME Keyring, KWallet), or similar OS-provided credential storage. |
| `CRED.BROWSER` | Browser Credential Access | Reading browser password databases, cookie stores, session storage, saved form data, or extension data. Targets Chrome, Firefox, Safari, Edge, and their profile directories. |
| `CRED.CLOUD` | Cloud Credential Files | Accessing cloud provider credential files: `~/.aws/credentials`, `~/.config/gcloud/`, Azure CLI tokens, Kubernetes configs (`~/.kube/config`), or similar. |
| `CRED.SSH` | SSH Key Access | Reading SSH private keys, `known_hosts`, or SSH agent sockets. Enables lateral movement and access to remote systems. |
| `CRED.ENV` | Environment Variable Harvesting | Reading environment variables that commonly contain secrets: `AWS_SECRET_ACCESS_KEY`, `DATABASE_URL`, `API_KEY`, `TOKEN`, and similar patterns. Distinguished from benign config reading by targeting variables with known secret-bearing naming patterns. |
| `CRED.TOKEN` | Token / Session File Access | Reading authentication tokens, session files, OAuth tokens, JWT files, or API key files from known locations on disk. |
| `CRED.CERT` | Certificate and Private Key Access | Accessing TLS/SSL certificates, private keys, or certificate stores. May indicate MITM setup or impersonation. |

## Severity Baseline

All `CRED` subtypes are medium-to-high in isolation. In dependency/library code, credential access without clear documented purpose is very high.

## Escalation Factors

The following conditions increase the suspicion level of any `CRED` finding:

- **The access occurs in install-time or build-time code.** `CRED.*` in a `setup.py`, `postinstall` script, or build hook is very high severity. There is no legitimate reason for an install script to read `~/.aws/credentials`, query the OS keychain, or enumerate SSH keys. The Axios npm compromise harvested credentials specifically during the install phase.
- **Multiple credential types are accessed in the same execution path.** Code that reads `~/.aws/credentials`, then `~/.ssh/id_rsa`, then enumerates browser profile directories is conducting a sweep. Each additional store accessed adds confidence that the behavior is intentional collection, not incidental access.
- **Credential access is immediately followed by network activity.** The sequence `CRED.*` → `NETW.*` is the canonical credential theft pattern. If the network destination is an IP address, a recently registered domain, or a messaging webhook (Discord, Telegram), escalate immediately. The LiteLLM PyPI attack used AWS SigV4-signed requests to send harvested secrets to AWS Secrets Manager before lateral movement.
- **The access targets multiple platforms or paths for the same credential type.** Code that checks `~/.aws/credentials`, then `%USERPROFILE%\.aws\credentials`, then `AWS_ACCESS_KEY_ID` environment variables is writing to be portable across Windows, macOS, and Linux. Attackers write cross-platform credential harvesters; legitimate libraries that need cloud credentials use SDK defaults.
- **Credential access is preceded by reconnaissance.** `RECN.OS` or `RECN.USER` findings before `CRED.*` indicate the code is profiling the environment to locate the correct credential paths for the detected platform. This is systematic, not incidental.
- **The accessed credential material is encoded or encrypted before use or transmission.** If harvested credential content is base64-encoded, XOR'd, or otherwise transformed (`OBFS.*`) before being written or sent, the obfuscation exists to conceal the stolen material in transit or storage.
- **The package has no documented credential management purpose.** A password manager SDK, an AWS CLI wrapper, or an authentication library may legitimately touch credential stores. A date formatting library, a logging utility, or an HTTP client with no documented cloud integration has no reason to read any credential file.
- **The access targets browser credential databases (`CRED.BROWSER`).** Browser credential access is almost never a legitimate dependency behavior. SQLite reads of Chrome's `Login Data` or Firefox's `logins.json` outside of a documented browser integration tool are very high signal.
- **Environment variable harvesting (`CRED.ENV`) uses broad pattern matching.** Code that iterates `os.environ` and filters keys matching `*KEY*`, `*SECRET*`, `*TOKEN*`, `*PASS*`, or `*CRED*` is performing systematic secret extraction, not targeted configuration reading. The breadth of the pattern is the signal.
- **`CRED.CERT` access is combined with traffic interception patterns.** Certificate or private key access paired with `NETW.LISTEN`, TLS manipulation, or proxy configuration suggests MITM setup rather than certificate management.

## De-escalation Factors

The following conditions reduce — but do not eliminate — suspicion:

- **The package's documented purpose involves credential management.** An AWS SDK, a password vault client, an SSH key management utility, or an authentication library that accesses credentials consistent with its stated functionality is behaving as expected. Verify that the specific access matches the documented scope — an AWS SDK reading `~/.aws/credentials` is expected; the same SDK reading browser cookie stores is not.
- **The credential access is to the package's own configuration files.** A tool that stores its own API key in a dedicated config file and reads that file at startup is not harvesting credentials. The distinction is between accessing third-party credential stores and accessing the package's own stored configuration.
- **The access is driven by explicit user invocation, not automatic execution.** Library code that performs credential access only when called with explicit parameters by application code (i.e., no self-executing install hooks, no `import`-time execution) is lower risk than code that accesses credentials as a side effect of being loaded.
- **A well-known, audited SDK or authentication framework is mediating the access.** Code that calls `boto3.Session()` to resolve credentials via the standard AWS credential chain is using an audited SDK that follows documented behavior. Code that directly reads `~/.aws/credentials` with `open()` bypasses the SDK abstraction and warrants more scrutiny regardless of intent.

> **Important caveat:** A legitimate package that touches credential stores can be compromised by a single malicious version. De-escalation based on package reputation or past behavior is only valid for the specific version under review. Credential access with network transmission is not de-escalatable — even a well-known package has no legitimate reason to exfiltrate credentials.

## Common Combinations

| Combination | Suggests | Escalation |
|---|---|---|
| `CRED.*` + `NETW.*` | Credential exfiltration — the complete theft chain | Very high — this is the canonical supply chain attack objective; verify destination |
| `CRED.CLOUD` + `NETW.HTTP` | Cloud credential theft with HTTP exfiltration | Very high — matches the Axios npm attack pattern; decode any payloads before sending |
| `CRED.ENV` + `NETW.WEBHOOK` | Environment secret harvesting via messaging webhook | Very high — Discord/Telegram webhook exfiltration of secrets; common in npm attacks |
| `CRED.*` + `OBFS.*` | Credential access concealed by obfuscation | High — the obfuscation exists to hide what is being accessed or transmitted |
| `CRED.*` + `PKGM.INSTALL` | Credential access at install time | Very high — install scripts have no legitimate credential access use case |
| `CRED.CLOUD` + `CRED.SSH` + `CRED.BROWSER` | Multi-store credential sweep | Very high — systematic collection across stores indicates an intentional, comprehensive harvester |
| `RECN.OS` + `CRED.*` | Platform detection preceding credential access | High — the reconnaissance is identifying which platform-specific credential paths to target |
| `CRED.*` + `FSYS.ARCHIVE` | Credentials collected and packaged | High — archiving suggests bulk collection prior to exfiltration |
| `CRED.CERT` + `NETW.LISTEN` | Certificate access with network listener | High — possible MITM setup; assess whether a proxy or listener is being configured |
| `CRED.ENV` + `ARTF.STR` | Sensitive environment variable names hardcoded as targets | Medium-high — hardcoded target patterns (`AWS_SECRET_ACCESS_KEY`, `DATABASE_URL`) confirm intentional targeting |

## Disambiguation

### CRED vs. FSYS

`CRED` and `FSYS.SENSITIVE` frequently overlap when the access method is a direct file read of a known credential path. Classify as `CRED.*` when the target is a credential store and the intent is clearly credential access — reading `~/.aws/credentials` is `CRED.CLOUD`, not `FSYS.READ`. Use `FSYS.SENSITIVE` when the path is sensitive but the credential classification is ambiguous, or when the access is to a directory containing both credential and non-credential files. When both apply, flag both: `CRED.CLOUD` + `FSYS.SENSITIVE` provides more signal to the triage analyst than either alone.

### CRED.ENV vs. benign configuration reading

Every application reads environment variables. The distinguishing factor for `CRED.ENV` is pattern: code that reads `os.environ.get("MY_APP_LOG_LEVEL")` is configuration reading. Code that iterates all environment variables and selects those matching `*SECRET*`, `*KEY*`, `*TOKEN*`, `*PASS*`, or `*CRED*` is credential harvesting. The boundary case is code that reads a single well-known variable (`DATABASE_URL`, `REDIS_URL`) for a plausible operational purpose — apply context. If the variable value is transmitted over the network, it is `CRED.ENV` regardless of stated purpose.

### CRED.TOKEN vs. CRED.CLOUD

Both involve reading authentication tokens from files. `CRED.CLOUD` is specifically for files in the canonical credential locations of cloud provider CLIs (`~/.aws/`, `~/.config/gcloud/`, `~/.kube/`). `CRED.TOKEN` covers authentication tokens that do not fit a specific cloud CLI pattern: OAuth token cache files, JWT files in application directories, `.npmrc` auth tokens, GitHub CLI tokens (`~/.config/gh/`), generic API key files. When in doubt: if it is a cloud CLI credential file, use `CRED.CLOUD`; if it is a general-purpose token or session file, use `CRED.TOKEN`.

### CRED.BROWSER vs. CRED.TOKEN

Browser credential access (`CRED.BROWSER`) is the access to browser-managed stores: password databases, cookie stores, and session storage maintained by the browser. `CRED.TOKEN` covers token files that live outside the browser but may contain authentication material for web services (e.g., an OAuth token cached by a CLI tool). Reading Chrome's `Login Data` SQLite file is `CRED.BROWSER`. Reading a `~/.github/token` file is `CRED.TOKEN`.

### CRED.SSH vs. lateral movement intent

`CRED.SSH` is classified as `CRED` because SSH private keys are authentication material, but the downstream consequence differs from other `CRED` subtypes. Cloud credentials and API tokens enable API abuse; SSH keys enable system access and lateral movement. `CRED.SSH` combined with `RECN.NET` (network discovery) or `NETW.*` to a system other than the C2 endpoint suggests the stolen keys will be used for lateral movement, not just sold or used for API access. Note this in the finding.

## Investigation Questions

When a `CRED` finding is detected, answer these questions to drive the investigation:

### For any CRED subtype:

1. **Where in the execution lifecycle does the credential access occur?** Install time, import time, or explicit function call? Install-time and import-time access are the highest-risk triggers — the developer may not have invoked any code intentionally.
2. **Is the accessed credential material transmitted over the network?** Trace the variable holding the credential data through the codebase. Does it reach any network call, file write, or encoded output? The access alone is suspicious; transmission confirms theft.
3. **What is the package's stated purpose, and does it explain this credential access?** The justification must be specific, not general. "It needs to authenticate" is not an explanation for reading browser cookie stores.
4. **Was this credential access present in previous versions?** Diff the current version against prior releases. Newly introduced credential access in a maintenance update is a high-confidence signal of supply chain compromise.
5. **How many distinct credential stores or types are accessed?** A single targeted access may be explained by documented functionality. A sweep across cloud credentials, SSH keys, browser data, and environment variables in a single code path is not.

### For CRED.CLOUD specifically:

6. **Does the package have documented cloud provider integration?** If the package has no stated AWS, GCP, or Azure integration and is reading cloud credential files, the access is unexplained.
7. **Is the access using the official SDK credential chain or direct file reads?** Direct `open("~/.aws/credentials")` bypasses SDK auditing and is more suspicious than `boto3.Session()`, which implements the standard credential chain with documented behavior.

### For CRED.BROWSER specifically:

8. **What specific browser database or store is targeted?** `Login Data` (passwords), `Cookies` (session tokens), `Web Data` (form data), or `Local State` (encryption key for cookie decryption)? The combination of `Login Data` + `Local State` is the complete Chrome password extraction chain.
9. **Does the package have any documented browser integration?** Almost no legitimate library dependencies require browser database access. If there is no documented browser automation or integration purpose, this finding is very high.

### For CRED.ENV specifically:

10. **Is the code reading specific named variables or scanning all environment variables?** Bulk scanning with pattern matching (`*TOKEN*`, `*KEY*`) is systematic harvesting. Reading a single named variable for a documented operational purpose is configuration.
11. **What happens to the value after it is read?** Is it used locally (passed to an SDK, used for authentication), logged, or transmitted? Local use is lower risk; transmission is confirmation of theft.

### For CRED.SSH specifically:

12. **Is the SSH key access combined with network reconnaissance or outbound connections to non-C2 endpoints?** SSH key theft that is paired with `RECN.NET` or connections to multiple external hosts suggests the keys will be used for lateral movement, which substantially expands the blast radius of the incident.
