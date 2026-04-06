# PKGM — Package and Build Manipulation

**Applies to:** Source (primarily package metadata, build scripts, install hooks).

## Description

Abuse of package management systems, build tools, and software distribution mechanisms to execute code or manipulate the software supply chain. This category addresses the *delivery mechanism* of supply chain attacks. Install-time code execution, dependency manipulation, and build system abuse are the vectors through which malicious payloads enter development environments and production systems.

## Subtypes

| Subtype ID | Name | Description |
|---|---|---|
| `PKGM.INSTALL` | Install-Time Execution | Code that runs during package installation: npm `postinstall`/`preinstall` scripts, Python `setup.py` execution, Ruby `extconf.rb`, Go `generate` directives that run at build time. The primary delivery mechanism for supply chain attacks. |
| `PKGM.BINDOWN` | Binary Download During Build | Downloading compiled binaries during installation or build rather than building from source. The downloaded binary is opaque to source-level analysis. |
| `PKGM.DEPMANIP` | Dependency Manipulation | Modifying lock files, dependency specifications, or resolution configuration to pull in unexpected packages. Includes dependency confusion attacks (publishing internal package names to public registries). |
| `PKGM.PHANTOM` | Phantom Dependency | A dependency declared in a package manifest (`package.json`, `requirements.txt`, `Cargo.toml`, etc.) that is **never imported, required, or referenced anywhere in the package's source code**. The dependency exists solely to trigger side effects during installation — typically a `postinstall` hook. A grep across all source files confirming zero usage is a powerful, automatable detection signal. The Axios compromise is the textbook example: `plain-crypto-js@^4.2.1` was added to `package.json` but never `require()`'d or imported in any of the 86 files in the package — it existed only to execute its `postinstall` hook during `npm install`. Distinguished from `PKGM.DEPMANIP` (which covers manipulation of dependency resolution) in that phantom dependencies are syntactically valid and resolve normally — the anomaly is that the resolved package is never *used* by the depending code. |
| `PKGM.HOOK` | Build System Hook | Modifying build system configuration (Makefile, CMakeLists, Gradle, webpack config) to inject execution during the build process. |
| `PKGM.PUBLISH` | Publication Anomaly | Indicators in package metadata that suggest suspicious publication: version number gaps, inconsistent authorship, republication under a new name, or automated publication patterns. |

## Severity Baseline

`PKGM.INSTALL` combined with `NETW` or `EXEC` is very high. `PKGM.BINDOWN` is high because it bypasses source analysis entirely. `PKGM.PHANTOM` is high — a dependency with zero source references has no legitimate purpose in the manifest.

## Escalation Factors

The following conditions increase the suspicion level of any `PKGM` finding:

- **`PKGM.INSTALL` combined with `NETW.*`.** Any install-time script that opens a network connection is nearly always malicious. Legitimate packages do not need to exfiltrate or fetch data during installation.
- **`PKGM.PHANTOM` dependency has an install hook.** A declared dependency that is never imported but runs a `postinstall` hook is the canonical supply chain attack pattern. The Axios compromise used `plain-crypto-js@^4.2.1` — present in `package.json` but never `require()`'d anywhere in 86 files. It existed solely to execute its `postinstall` hook during `npm install`. Treat as confirmed hostile until proven otherwise.
- **`PKGM.BINDOWN` fetches from a non-canonical host.** Binaries fetched from domains outside the package registry's own CDN or the project's official release infrastructure bypass all upstream integrity controls.
- **`PKGM.BINDOWN` without checksum verification.** Absence of hash validation means any MITM or CDN compromise delivers an arbitrary binary silently.
- **`PKGM.PUBLISH` version gap with authorship change.** A gap in the published version history combined with a new or unfamiliar maintainer account is a strong indicator of account takeover prior to a malicious release.
- **`PKGM.DEPMANIP` against a pinned lock file.** Modifications to a committed lock file not traceable to a deliberate dependency update indicate either a compromised contributor workflow or a build-time substitution attack.
- **`PKGM.HOOK` in a transitive dependency.** Build system hooks injected by a transitive (not direct) dependency are harder to audit and rarely legitimate; escalates to high regardless of other signals.
- **Any PKGM subtype in a package with high downstream reach.** Compromise of a widely-depended-on package multiplies blast radius. Registry download count and reverse-dependency count are relevant escalation context.
- **`PKGM.INSTALL` script is obfuscated or encoded.** Base64, char-code construction, or whitespace obfuscation inside a `postinstall` script is an independent escalation signal (compound `PKGM` + `OBFS`).
- **`PKGM.PHANTOM` package name is a plausible variant of a legitimate package.** Suggests deliberate name selection to avoid scrutiny, consistent with a planned compromise rather than accidental inclusion.

## De-escalation Factors

The following conditions reduce — but do not eliminate — suspicion:

- **`PKGM.INSTALL` script is fully auditable and behavior-stable across versions.** If the install script's logic is stable across the project's full version history and its behavior is bounded (e.g., compiling a native addon from vendored source with no network calls), the signal drops significantly. Still verify the vendored source.
- **`PKGM.BINDOWN` from an official, integrity-verified release URL.** Download of a pre-built binary is less concerning when the URL is the project's canonical release endpoint (e.g., GitHub Releases), the download is gated on a verified checksum, and the pattern is consistent across the project's version history. *(Caveat: upstream release infrastructure can itself be compromised.)*
- **`PKGM.PHANTOM` is an optional/platform-specific dependency documented in the project's changelog.** Some ecosystems declare optional or platform-specific dependencies that may not be imported on all targets. *(Caveat: the Axios compromise used exactly this ambiguity as cover; verify that the dependency's install hook is absent or inert.)*
- **`PKGM.DEPMANIP` change is attributed to an authenticated automated dependency update tool.** Lock file modifications made by Dependabot, Renovate, or similar with a matching PR and approval trail are lower risk. *(Caveat: dependency confusion attacks can generate superficially legitimate update PRs.)*
- **`PKGM.PUBLISH` anomaly is explained by a documented project transfer.** Package transfers between maintainers are legitimate but should be corroborated by public announcements, issue tracker references, or registry transfer records — not solely by the package metadata itself.

> **Important caveat:** PKGM findings are inherently supply chain risk — they concern the delivery mechanism, not the payload. De-escalation of the delivery mechanism does not address what the delivered code does. Always investigate the payload independently.

## Common Combinations

| Combination | Suggests | Escalation |
|---|---|---|
| `PKGM.PHANTOM` + `PKGM.INSTALL` + `NETW.*` | Classic supply chain implant: phantom dep exists solely to run a network-calling install hook (the Axios/plain-crypto-js pattern) | Critical |
| `PKGM.INSTALL` + `EXEC.*` + `OBFS.*` | Install hook executing obfuscated code | Critical — payload delivery with active evasion |
| `PKGM.BINDOWN` + `EXEC.*` | Downloaded binary executed at build time; source analysis entirely bypassed | High |
| `PKGM.DEPMANIP` + `PKGM.PUBLISH` (version gap) | Lock file tampered to pull a specific version coinciding with suspicious publication | High — coordinated substitution attack |
| `PKGM.HOOK` + `NETW.*` | Build system hook (Makefile, CMake, Gradle) making outbound network calls during compilation | High |
| `PKGM.PUBLISH` (new maintainer) + `PKGM.INSTALL` | Maintainer account takeover followed by malicious install hook injection | High |
| `PKGM.PHANTOM` + typosquatted name | Phantom dependency name is a typosquat of a legitimate package | High — deliberate camouflage |
| `PKGM.INSTALL` + `PRST.*` | Install hook establishing persistence (cron, launchd, registry key) on the developer's machine | High — extends compromise beyond the build environment |
| `PKGM.BINDOWN` + `OBFS.*` | Binary download with obfuscated retrieval logic (encoded URL, staged redirect) | High — active evasion of URL-based controls |
| `PKGM.DEPMANIP` + `CRED.*` | Dependency substitution paired with credential access | Critical — the substituted package is a credential harvester |

## Disambiguation

### PKGM.INSTALL vs. EXEC

`PKGM.INSTALL` identifies that execution is triggered by the package manager's own hook mechanism — the `postinstall` field in `package.json`, the `cmdclass` in `setup.py`, the `extconf.rb` in a RubyGem. The malicious code runs because the package ecosystem grants that entry point.

`EXEC` identifies arbitrary command execution as a behavior that appears in code — `os.system`, `subprocess.Popen`, `eval()` — regardless of when or how it is reached.

Apply both when an install hook contains dynamic command execution. Apply only `PKGM.INSTALL` when the install script's commands are static and fully enumerable. Apply only `EXEC` when the execution pattern appears in runtime code with no install-time trigger. The combination `PKGM.INSTALL` + `EXEC` means the package manager automatically delivers a code execution primitive to every developer who installs the package.

### PKGM.PHANTOM vs. PKGM.DEPMANIP

`PKGM.PHANTOM` describes a dependency that is declared but never imported or called by the project's own code. The Axios compromise is the canonical case: `plain-crypto-js` appeared in `package.json` but no `require('plain-crypto-js')` existed anywhere in the source. The threat model is that the phantom package's install hook runs automatically regardless of whether the code uses it.

`PKGM.DEPMANIP` describes modification of the dependency resolution mechanism — the lock file, the requirements file, the go.sum — in a way that alters which package or version resolves without necessarily changing the manifest. The threat model is substitution: the developer believes they are installing package X at version Y, but the manipulated resolver fetches something different.

When a package is both phantom and was introduced by a lock file modification not traceable to a legitimate update, apply both subtypes.

### PKGM.HOOK vs. PKGM.INSTALL

`PKGM.INSTALL` is scoped to hooks natively supported by the language's package manager. `PKGM.HOOK` covers injection into the broader build system — Makefiles, CMakeLists, Gradle files, webpack configs. A `postinstall` entry in `package.json` that invokes `make` bridges both: the initial trigger is `PKGM.INSTALL`, and any malicious logic in the Makefile is `PKGM.HOOK`.

### PKGM.PUBLISH vs. Contextual Signal

`PKGM.PUBLISH` anomalies — version gaps, authorship changes, unusual publication timing — are rarely sufficient findings in isolation. They function as context that escalates other findings. Do not open a `PKGM.PUBLISH` finding without pairing it with at least one behavioral finding or a documented external event (account takeover report, registry advisory) that gives the anomaly operational meaning.

## Investigation Questions

When a `PKGM` finding is detected, answer these questions to drive the investigation:

### For any PKGM subtype:
1. **Is the flagged package a direct or transitive dependency, and how many hops separate it from the project?** Deeper transitive dependencies receive less routine scrutiny and are a preferred insertion point for attackers.
2. **What is the package's download volume and reverse-dependency count?** High reach multiplies severity and is relevant to incident scope.
3. **Does the version in use match the committed lock file, and is the lock file change traceable to a known author with justification?**
4. **Has the package's registry page, repository, or maintainer accounts shown anomalous activity in the window surrounding this version?**

### For PKGM.INSTALL specifically:
5. **What is the complete set of commands executed by the install hook?** Can the hook's behavior be fully determined by static reading, or does it contain dynamic construction, encoded strings, or fetched scripts?
6. **Has the install hook content changed across the last three published versions?** What changed and does the diff align with the stated changelog?
7. **Does the install hook make any network calls, write files outside its own directory, or register persistent mechanisms?**

### For PKGM.PHANTOM specifically:
8. **Is there any code path that would legitimately explain why this package is declared but not imported?** Conditional import, optional feature, test-only usage? If not, what justifies its presence?
9. **Does the phantom package itself have an install hook?** If yes, treat as `PKGM.PHANTOM` + `PKGM.INSTALL` and escalate immediately.

### For PKGM.BINDOWN specifically:
10. **What is the download URL, and does it resolve to infrastructure controlled by the package's official maintainers?**
11. **Is the downloaded binary verified against a checksum or signature before execution?** If not, what is the blast radius?

### For PKGM.DEPMANIP specifically:
12. **What specific change was made to the lock file or resolution configuration?** Who made it, and is there a corresponding PR with review and approval? Does the changed entry resolve to the intended registry namespace?
