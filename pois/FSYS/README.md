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
| `FSYS.CLIPBOARD` | Clipboard Access | Reading or writing system clipboard contents. The clipboard is a shared data surface that crosses application boundaries — any process can read what a user copied from any other application. Reading enables passive data theft (passwords copied from a password manager, cryptocurrency addresses, sensitive text). Writing enables clipboard hijacking: silently replacing a copied cryptocurrency address with an attacker's address so the next paste sends funds to the wrong wallet. On most operating systems, clipboard access requires no special permissions, making it a low-friction data access vector. |

## Severity Baseline

`FSYS.SENSITIVE` is high in isolation. `FSYS.CLIPBOARD` is medium-high — clipboard access in a library with no UI functionality is suspicious. `FSYS.READ` and `FSYS.WRITE` depend heavily on target and context.
