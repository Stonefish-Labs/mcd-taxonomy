# BP-SUPPLY — Supply Chain Payload

## Description

A package or dependency that executes a malicious payload during installation or first use. This is the dominant attack pattern in modern software supply chains: a package runs code at install time that downloads a second stage, exfiltrates credentials, or establishes persistence — all before the developer has written a single line of code that uses the package.

## Constituent POIs

| Role | POI | Notes |
|---|---|---|
| **Required** | `PKGM.INSTALL` | Install-time execution is the entry point |
| **Required** | `EXEC.SHELL` or `NETW.*` or `FSYS.WRITE` | The payload must *do* something: execute commands, phone home, or drop files |
| Supporting | `OBFS.*` | Obfuscation of install-time code strongly escalates |
| Supporting | `ARTF.URL` or `ARTF.IP` | Hardcoded remote targets in install scripts |
| Supporting | `PKGM.BINDOWN` | Downloading binaries during install |
| Supporting | `EVSN.ENVCHECK` | Checking whether the environment is CI/sandbox before activating |
| Supporting | `PKGM.PHANTOM` | Install-time payload delivered via a dependency that is never imported in source |
| Supporting | `EVSN.FORENSIC` | Self-destruction or evidence replacement after payload execution |
| Supporting | `EVSN.MASQ` | Payload artifacts masquerading as legitimate system components |

## Real-World Analogue

The `ua-parser-js` hijack (2021), the `event-stream` attack (2018), the `colors`/`faker` sabotage (2022), the `axios` npm supply chain compromise (2026) — attacker hijacked the lead maintainer's npm account, injected a phantom dependency (`plain-crypto-js`) whose `postinstall` hook deployed a cross-platform RAT, then swapped clean decoys into place to destroy evidence. Package install triggers immediate malicious execution.

## Investigation Guidance

- **Verify:** What does the install script actually do? Trace the full execution path from the install hook.
- **Escalates:** Install script is obfuscated. Install script contacts a remote host. Install script writes to locations outside its package directory. Package is new, low-download-count, or has anomalous metadata.
- **De-escalates:** Install script compiles native extensions from included source. Install script is documented and runs a standard build tool. Package has a long history and many maintainers.
