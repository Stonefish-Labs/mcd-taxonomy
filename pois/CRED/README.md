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
