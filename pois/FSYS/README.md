# FSYS — Filesystem Operations

**Applies to:** Source and binary.

## Description

Any operation that reads, writes, modifies, enumerates, or deletes files and directories on the local system. Filesystem access was historically excluded from detection taxonomies because the search space was too large to analyze comprehensively. That constraint no longer applies. Filesystem operations are central to nearly every malicious behavior: credential theft reads files, droppers write files, ransomware modifies files, and reconnaissance enumerates them.

## Subtypes

| Subtype ID | Name | Description |
|---|---|---|
| `FSYS.READ` | File Read | Reading file contents. Suspicious when targeting known sensitive paths (credentials, keys, configuration, browser data). |
| `FSYS.WRITE` | File Write | Creating or modifying files. Suspicious when writing to system directories, startup locations, or when the written content is executable. |
| `FSYS.DELETE` | File Deletion | Removing files. May indicate evidence destruction, anti-forensics, or disabling security tools. |
| `FSYS.ENUM` | Directory Enumeration | Listing directory contents, walking directory trees, or searching for files matching patterns. A precursor to targeted access or bulk collection. |
| `FSYS.PERM` | Permission Modification | Changing file ownership, permissions, or ACLs. May indicate privilege setup, making files executable, or weakening access controls. |
| `FSYS.LINK` | Symbolic/Hard Link Manipulation | Creating, modifying, or following symlinks in ways that could redirect access to unintended targets (symlink attacks). |
| `FSYS.TEMP` | Temporary File Operations | Creating files in temp directories. Common staging ground for payloads because temp directories are writable, often unmonitored, and expected to contain arbitrary content. |
| `FSYS.ARCHIVE` | Archive Operations | Creating, extracting, or manipulating compressed archives (zip, tar, gzip). Archive creation is a common pre-exfiltration step. Extraction may be a dropper unpacking a payload. |
| `FSYS.SENSITIVE` | Sensitive Path Access | Access to specifically sensitive filesystem locations: SSH directories, browser profiles, cloud credential files, password databases, keychain files, certificate stores. This is a high-signal subtype that overlaps with `CRED` when the target is a credential. |
| `FSYS.HIDDEN` | Hidden Storage Mechanisms | Using platform-specific filesystem features to store data in locations invisible to standard file listing tools and casual inspection. Includes: **NTFS Alternate Data Streams (ADS)** — attaching data to existing files via the `:stream` syntax (`file.txt:payload`), invisible to `dir`, Explorer, and most file management tools; **macOS extended attributes and resource forks** — storing data via `xattr` in custom or Apple-namespaced attributes, or in the legacy resource fork (`/..namedfork/rsrc`), invisible to standard `ls` output; **Linux extended attributes** — storing data via `setxattr()` / `getxattr()` in the `user.*` or `security.*` namespace, invisible to standard directory listings; **hidden file attributes** — programmatically setting Windows hidden/system attributes via `SetFileAttributes()` or `attrib +h +s`, or creating dot-prefixed files in unexpected locations on Unix systems; **reserved/device name abuse** — on Windows, using reserved device names (`CON`, `NUL`, `AUX`, `COM1`) or trailing dots/spaces in paths that are difficult to enumerate or delete with standard tools. Distinguished from `OBFS.STEGANOGRAPHY` (which hides data *within* another data format — embedding bytes in image pixels, audio LSBs, or PDF structure) in that `FSYS.HIDDEN` uses the filesystem's own metadata and storage layers to make data invisible to standard enumeration. The hidden data is not embedded in another file's visible content — it exists in a parallel storage layer that requires specific tools or API calls to access. |
| `FSYS.CLIPBOARD` | Clipboard Access | Reading or writing system clipboard contents. The clipboard is a shared data surface that crosses application boundaries — any process can read what a user copied from any other application. Reading enables passive data theft (passwords copied from a password manager, cryptocurrency addresses, sensitive text). Writing enables clipboard hijacking: silently replacing a copied cryptocurrency address with an attacker's address so the next paste sends funds to the wrong wallet. On most operating systems, clipboard access requires no special permissions, making it a low-friction data access vector. |

## Severity Baseline

`FSYS.SENSITIVE` is high in isolation. `FSYS.CLIPBOARD` is medium-high — clipboard access in a library with no UI functionality is suspicious. `FSYS.HIDDEN` is medium-high — legitimate use of ADS and extended attributes exists but is narrow; in a dependency context, hidden storage is a strong evasion signal. `FSYS.READ` and `FSYS.WRITE` depend heavily on target and context.

## Escalation Factors

The following conditions increase the suspicion level of any `FSYS` finding:

- **Sensitive path targeting.** Access to `/etc/passwd`, `~/.ssh/`, `~/.aws/credentials`, browser profile directories, keychain files, or OS credential stores elevates any FSYS subtype to high regardless of the operation type.
- **Write followed by execute.** `FSYS.WRITE` to a temp or world-writable directory (`/tmp`, `%TEMP%`, `/var/tmp`) immediately followed by execution of the written file is the canonical payload staging pattern. The Axios compromise wrote a script to `/tmp` and executed it via `nohup python3 /tmp/ld.py`. This combination is critical.
- **Archive creation targeting user data directories.** `FSYS.ARCHIVE` creation scoped to `~/Documents`, `~/Desktop`, database files, or source code directories is a pre-exfiltration indicator. Archive creation on application-owned paths is not.
- **Enumeration of non-application directories.** `FSYS.ENUM` on directories the package has no plausible reason to know about (SSH directories, credential stores, cloud config paths, other installed applications) is suspicious. Enumeration of the package's own install tree is expected.
- **Permission modification downgrading visibility.** `FSYS.PERM` removing read or execute bits from log files, audit directories, or security tooling binaries is an anti-forensics indicator.
- **Deletion after anomalous write activity.** `FSYS.DELETE` in sequence after `FSYS.WRITE` or `FSYS.ARCHIVE` creation suggests anti-forensics cleanup. Stand-alone deletion of the package's own temp files does not escalate.
- **Symbolic link creation outside the package tree.** `FSYS.LINK` creating symlinks that redirect sensitive system paths or escape a sandbox boundary elevates severity.
- **Clipboard access with no user-initiated trigger.** `FSYS.CLIPBOARD` in code that executes on install, import, or background thread rather than in response to an explicit user action is inherently suspicious. No legitimate library reads the clipboard without a user event.
- **Cross-user or cross-privilege path access.** Reads or writes to paths belonging to other user accounts, or to system paths requiring elevated privilege, indicate privilege escalation attempts or targeting of other users.
- **Hardcoded absolute sensitive paths.** Sensitive paths embedded as string literals rather than constructed from environment variables or OS APIs indicate deliberate targeting rather than incidental access.
- **`FSYS.HIDDEN` stores executable content or credential material.** ADS or extended attributes used to store shell scripts, binary payloads, encryption keys, or exfiltrated credentials are high-severity regardless of the host file.
- **`FSYS.HIDDEN` attaches data to system files or files owned by other packages.** Writing an ADS to `C:\Windows\System32\notepad.exe` or an xattr to `/usr/bin/python3` piggybacks on trusted files and may survive OS updates that only check the primary data stream.
- **`FSYS.HIDDEN` is combined with `FSYS.WRITE` to the same path.** Writing visible content to a file and hidden content to the same file's ADS/xattr suggests the visible content is a decoy and the hidden content is the payload.
- **The hidden storage mechanism is read back and passed to `LOAD.*` or `EXEC.*`.** Data stored in hidden streams or attributes that is subsequently retrieved and executed is a staged payload delivery pattern using hidden storage as an evasion layer.

## De-escalation Factors

The following conditions reduce — but do not eliminate — suspicion:

- **Access limited to the package's declared install tree.** Reads and writes confined to paths the package manager created for this package are expected behavior. Scope creep beyond that boundary warrants scrutiny.
- **Temp file write paired with documented cache or build behavior.** `FSYS.WRITE` to a temp directory is less suspicious when the package's documented purpose involves compilation, caching, or build artifact management. *(Caveat: this does not de-escalate write-then-execute patterns.)*
- **Archive operations on paths passed in by the calling application.** `FSYS.ARCHIVE` on paths provided as arguments by the consuming application reflects the library's stated function (e.g., a compression library compressing what it is told to compress).
- **Permission changes on self-owned config files at install time.** A package setting `0600` on a config file it just created is standard hardening. Verify the target path is genuinely owned by the package.
- **Enumeration of XDG/standard directories for application data location.** Some packages enumerate standard OS directories to locate their own data. De-escalate only when enumeration does not extend to credential or security-sensitive paths.
- **`FSYS.HIDDEN` using macOS extended attributes for Finder metadata or quarantine flags.** macOS uses `com.apple.quarantine`, `com.apple.FinderInfo`, and other system xattrs for legitimate OS-level metadata. Tools that read or write these specific Apple-namespaced attributes as part of documented file management are expected. *(Caveat: custom-namespaced xattrs or xattrs with binary/encoded payloads do not de-escalate.)*
- **`FSYS.HIDDEN` in a backup, archive, or file synchronization tool.** Tools that preserve file metadata (rsync, backup utilities, archive managers) may read and write ADS, extended attributes, and resource forks as part of faithful file reproduction. De-escalate only when the package's documented purpose is file management and the hidden data originates from the source files being processed, not from the tool itself.

> **Important caveat:** Filesystem operations are the broadest category in this taxonomy. The path being accessed, not the operation type, determines severity. A `FSYS.READ` of `~/.ssh/id_rsa` is fundamentally different from a `FSYS.READ` of the package's own `config.json`. Always resolve the full path before assessing.

## Common Combinations

| Combination | Suggests | Escalation |
|---|---|---|
| `FSYS.SENSITIVE` + `NETW.*` | Credential or config file read, contents exfiltrated over network | Critical — the complete data theft chain |
| `FSYS.WRITE` (temp) + `EXEC.*` | Payload written to temp directory and executed — canonical dropper pattern | Critical |
| `FSYS.ARCHIVE` + `NETW.*` | Archive created from user data, transmitted out — data exfiltration staging | Critical |
| `FSYS.ENUM` + `FSYS.SENSITIVE` | Directory traversal locating credential or config targets before access | High |
| `FSYS.DELETE` + `EVSN.FORENSIC` | Post-activity cleanup of dropped files or logs — anti-forensics | High |
| `FSYS.CLIPBOARD` + `NETW.*` | Clipboard content exfiltrated — targets passwords, seed phrases, session tokens | High |
| `FSYS.WRITE` + `FSYS.PERM` | File written then made executable or world-writable — privilege setup | High |
| `FSYS.SENSITIVE` + `CRED.*` | Target path is a credential file — FSYS identifies the method, CRED identifies the intent | High to Critical |
| `FSYS.LINK` + `FSYS.WRITE` | Symlink redirect followed by write — path traversal or symlink attack | High |
| `FSYS.TEMP` + `OBFS.*` | Obfuscated code writing to temp directory — concealed payload staging | Critical |
| `FSYS.HIDDEN` + `EXEC.*` or `LOAD.*` | Data stored in hidden stream/attribute, then retrieved and executed — staged payload in invisible storage | Critical |
| `FSYS.HIDDEN` + `CRED.*` | Credentials written to hidden storage — invisible credential cache for later retrieval or exfiltration | High |
| `FSYS.HIDDEN` + `EVSN.FORENSIC` | Hidden storage combined with anti-forensic cleanup — payload hidden in ADS/xattr while visible traces are wiped | High |
| `FSYS.HIDDEN` + `PRST.*` | Hidden data used as a persistence mechanism — payload survives standard file cleanup because cleanup tools don't see it | High |

## Disambiguation

### FSYS.SENSITIVE vs. CRED

These two classifications overlap when the target path is a file that contains credentials. They are not mutually exclusive.

Classify as `FSYS.SENSITIVE` when the path is sensitive but the content is not confirmed to be credential material — OS config files, application settings, certificate stores, or paths that vary in content across environments.

Classify as `CRED.*` (with `FSYS.SENSITIVE` as a supporting indicator) when the target path is a known credential file: `~/.aws/credentials`, `~/.netrc`, `~/.ssh/id_rsa`, browser login databases (`Login Data`, `key4.db`), or any path that by structure reliably contains authentication material.

In investigation records, carry both classifications. The `CRED` classification drives escalation priority; the `FSYS.SENSITIVE` classification captures the operational method.

### FSYS.HIDDEN vs. OBFS.STEGANOGRAPHY

Both hide data from casual observation, but using fundamentally different mechanisms. `OBFS.STEGANOGRAPHY` hides data *within the content* of another file — embedding bytes in image pixel LSBs, audio samples, PDF structure, or whitespace characters. The host file's visible purpose (an image, a document) is unrelated to the hidden payload. Detection requires content-aware analysis.

`FSYS.HIDDEN` hides data *in the filesystem's own metadata and storage layers* — NTFS Alternate Data Streams, extended attributes, resource forks, hidden file attributes. The data exists in a parallel storage mechanism that standard file listing tools simply don't display. Detection requires platform-aware enumeration (e.g., `dir /r` for ADS, `xattr -l` for macOS, `getfattr` for Linux).

When data is stored in an ADS or xattr AND the content of that hidden stream is itself steganographically encoded, both tags apply.

### FSYS.HIDDEN vs. FSYS.WRITE

`FSYS.WRITE` covers writing to the primary data stream of a file — the content visible to standard tools. `FSYS.HIDDEN` covers writing to parallel storage layers associated with a file or filesystem location. When a package writes both a visible file and hidden data attached to it (a decoy file plus a payload ADS), tag both `FSYS.WRITE` and `FSYS.HIDDEN`.

### FSYS.CLIPBOARD: Why It Lives in FSYS

`FSYS.CLIPBOARD` is categorized under FSYS because clipboard access uses OS file and memory abstractions, but it is behaviorally distinct from all other FSYS subtypes. Standard FSYS indicators involve disk paths and file handles. `FSYS.CLIPBOARD` crosses application process boundaries without touching disk and without requiring elevated permissions on most operating systems.

The primary malicious targets of clipboard access are cryptocurrency wallet addresses (replaced in transit — address substitution attacks), passwords copied from password managers, session tokens, and seed phrases. `FSYS.CLIPBOARD` should always be treated as medium-high in isolation, with immediate escalation to high when implemented in a background thread, recurring timer, or on-import hook rather than in an explicitly invoked function.

### FSYS.TEMP vs. Normal Temp Usage

Nearly all software uses temporary files. The presence of `FSYS.TEMP` alone is not a signal. Flag `FSYS.TEMP` when:

- The written content is binary, a shell script, or matches a known payload structure
- The temp file is made executable before or after write
- The temp file is executed directly (`EXEC.SHELL`, `EXEC.PROC`) rather than read back into the application
- The temp file name is randomly generated to evade static detection
- The temp file is deleted immediately after execution — cleanup consistent with dropper tradecraft

Normal temp usage (crash recovery, build artifacts, download-then-move) does not require escalation.

### FSYS.DELETE vs. EVSN.FORENSIC

`FSYS.DELETE` is the filesystem operation. `EVSN.FORENSIC` is the evasion intent. When deletion targets files that were created or modified by the same package's malicious activity, classify both: `FSYS.DELETE` for the operation and `EVSN.FORENSIC` for the intent. When deletion targets the package's own legitimate temp files or cache, classify only `FSYS.DELETE` without `EVSN.FORENSIC`.

## Investigation Questions

When a `FSYS` finding is detected, answer these questions to drive the investigation:

### For any FSYS subtype:
1. **What is the full resolved path being accessed?** Trace the path construction to its origin — hardcoded string, environment variable, user input, or OS API — and resolve it to the actual filesystem location. Hardcoded sensitive absolute paths are higher severity than dynamically constructed ones.
2. **Does the package have a plausible functional reason to access this path?** Map the accessed path against the package's stated purpose. A markdown renderer accessing `~/.ssh/` has no legitimate explanation.
3. **What is the full operation sequence?** Reconstruct the chain: enumerate, read, write, archive, transmit, delete. A single `FSYS.WRITE` is medium priority. `FSYS.ENUM` -> `FSYS.SENSITIVE` -> `FSYS.ARCHIVE` -> `NETW.*` is critical.
4. **When in the package lifecycle does this code execute?** Install hooks, import-time code, and background threads are higher risk than callable functions.

### For FSYS.WRITE specifically:
5. **Is the write followed by execution of the written file?** This is the single highest-value question for temp file writes. If yes, classify the combination as critical regardless of other context.

### For FSYS.DELETE specifically:
6. **Is the deletion targeting files that the package itself wrote during anomalous activity?** Deletion of temp files, logs, or downloaded content in sequence after write or archive operations suggests anti-forensics cleanup.

### For FSYS.CLIPBOARD specifically:
7. **Is the clipboard access in a callable function or in autonomous code?** Determine whether it is gated on an explicit function call from the consuming application or runs in a background thread, timer, or at import time.

### For FSYS.HIDDEN specifically:
8. **What platform mechanism is used, and what is stored?** Identify the specific API (`CreateFile` with `:stream`, `setxattr`, `SetFileAttributes`, etc.), the host file or path, and the content of the hidden data. Binary or encoded content is higher severity than plaintext metadata.
9. **Is the hidden data read back by the same package?** Trace whether the hidden storage is subsequently accessed. If the package writes and reads its own hidden data, it is using hidden storage as a private channel — determine what the data is used for (execution, transmission, comparison).
10. **Does the host file belong to the package or to another component?** Hidden data attached to the package's own files is lower severity than hidden data attached to system files or files owned by other software.

### For FSYS.ARCHIVE specifically:
8. **What directory is being archived, and is the archive path application-owned?** An archive of `~/Documents` written to `/tmp` is pre-exfiltration staging. An archive of the package's own build output is expected.

### For FSYS.SENSITIVE specifically:
9. **Does the data read from the sensitive path flow into a network transmission function?** Trace the data through the codebase. If it reaches a network call — directly, through a variable, or through an encode/serialize step — the finding escalates to credential exfiltration.

### For FSYS.PERM specifically:
10. **Does the permission change target files outside the package's own tree?** Permission changes on system binaries, security tools, log directories, or files owned by other applications are not legitimate.

### Cross-cutting:
11. **Are path strings obfuscated or constructed to evade static analysis?** Paths assembled through string concatenation, base64 decoding, or character code arrays that obscure the final target are an `OBFS` indicator co-occurring with FSYS.
12. **Has this path pattern appeared in prior supply chain incidents?** Cross-reference against known incident IOCs. `/tmp` write-then-execute is the Axios pattern. Browser credential database paths are recurring targets in PyPI stealer campaigns.
