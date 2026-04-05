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
