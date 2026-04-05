# Points of Investigation (POIs)

A Point of Investigation is an atomic indicator: a single observable property of code or a binary that, when detected, warrants attention. POIs are the building blocks of the system. They are not verdicts. They are evidence.

## POI Definition

Every POI is defined by:

- **ID and Name** — A short mnemonic code and a human-readable name.
- **Description** — What the POI represents and why it matters.
- **Subtypes** — Specific variants within the category.
- **Severity Baseline** — A default assessment of how suspicious the POI is in isolation.
- **Applies To** — Whether the POI is observable in source code, binaries, or both.

## Categories

| ID | Name | Description |
|---|---|---|
| [ARTF](ARTF/) | Hardcoded Artifacts | Embedded values suggesting external targets, credentials, or infrastructure |
| [NETW](NETW/) | Network Communication | Any mechanism for sending/receiving data over a network |
| [FSYS](FSYS/) | Filesystem Operations | Reading, writing, modifying, enumerating, or deleting files |
| [EXEC](EXEC/) | Code Execution | Launching processes, executing commands, or invoking system primitives |
| [LOAD](LOAD/) | Dynamic Code Loading | Loading, compiling, or interpreting new executable logic at runtime |
| [OBFS](OBFS/) | Obfuscation | Techniques making code intentionally difficult to understand |
| [EVSN](EVSN/) | Evasion and Anti-Analysis | Detecting, resisting, or circumventing analysis environments |
| [CRED](CRED/) | Credential and Secret Access | Targeting authentication material, secrets, tokens, or keys |
| [PRST](PRST/) | Persistence | Ensuring continued execution across reboots or session changes |
| [PRIV](PRIV/) | Privilege Escalation | Gaining higher privileges than currently held |
| [RECN](RECN/) | System Reconnaissance | Gathering information about the host system and environment |
| [TIME](TIME/) | Temporal Operations | Time retrieval, comparison, delays, or time-conditioned execution |
| [PKGM](PKGM/) | Package and Build Manipulation | Abusing package management and build systems |
| [CRPT](CRPT/) | Cryptographic Operations | Crypto primitives in contexts where crypto is not the stated purpose |
| [AITM](AITM/) | AI-Targeted Manipulation | Content designed to manipulate AI systems processing the code |
| [RSRC](RSRC/) | Resource Manipulation | Consuming or exhausting system resources beyond stated functionality |

## Composition Effects

- Multiple POIs from **different categories** in the same scope are more suspicious than multiple POIs from the same category.
- **Obfuscation** (`OBFS.*`) acts as a severity **multiplier** on any co-occurring POI.
- **Evasion** (`EVSN.*`) acts as a severity **multiplier** — code that hides from analysis is assumed to have something worth hiding.
