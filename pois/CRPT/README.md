# CRPT — Cryptographic Operations

**Applies to:** Source and binary.

## Description

Use of cryptographic primitives — encryption, decryption, hashing, key generation, key exchange, certificate manipulation, or random number generation — in contexts where cryptographic functionality is not the stated purpose of the code. Cryptography is dual-use by nature: every legitimate encryption library uses the same primitives as ransomware. The signal comes from *context*: symmetric encryption of local files in a package that claims to be a string utility is a very different proposition than the same operation in a documented encryption library.

This category is deliberately broad because cryptographic operations are load-bearing components of nearly every malicious behavioral pattern: ransomware encrypts files, exfiltration encrypts stolen data, backdoors encrypt their C2 channels, credential theft hashes or verifies passwords. Detecting unexpected crypto is often the first thread you pull that unravels the full picture. The LiteLLM attack embedded a complete hybrid RSA-4096 + AES-256-CBC encryption pipeline and a full AWS SigV4 signing implementation — none of which had any relationship to LiteLLM's stated purpose as an LLM proxy.

## Subtypes

| Subtype ID | Name | Description |
|---|---|---|
| `CRPT.SYMENC` | Symmetric Encryption | AES, ChaCha20, Salsa20, 3DES, Blowfish, RC4, XOR cipher, or other symmetric encryption/decryption of data. In malware context: payload decryption, ransomware file encryption, encrypted C2 communication, or encrypting stolen data before exfiltration. The LiteLLM payload used AES-256-CBC with PBKDF2 key derivation to encrypt all harvested credentials before exfil. |
| `CRPT.ASYMENC` | Asymmetric Encryption | RSA, ECC, ElGamal, or other public-key encryption/decryption. In ransomware: encrypting the symmetric key with an attacker's public key to ensure only the attacker can decrypt. A hardcoded public key (`ARTF.CREDENTIAL`) paired with asymmetric encryption is a very strong indicator — it means the code is encrypting data that only a specific remote party can read. |
| `CRPT.KEYGEN` | Key Generation | Generating cryptographic keys — symmetric keys, asymmetric key pairs, or deriving keys from passwords/passphrases (PBKDF2, HKDF). Suspicious when keys are generated for undocumented purposes, transmitted externally, or generated ephemerally per-session (indicating encrypted C2 or per-victim ransomware keys). |
| `CRPT.RNG` | Cryptographic Random Number Generation | Accessing cryptographically secure random number generators: `/dev/urandom`, `CryptGenRandom`, `SecRandomCopyBytes`, `crypto.getRandomValues()`, `secrets` module, or `openssl rand`. Distinguished from general-purpose RNG (`math.random`, `rand()`) by intent — CSPRNG access indicates the code is performing security-sensitive operations. Also covers *deliberately weak* RNG: using a predictable seed or non-cryptographic RNG for operations that should use CSPRNG suggests intentionally breakable "encryption." |
| `CRPT.HASH` | Hashing | Computing cryptographic hashes (MD5, SHA-1, SHA-256, SHA-3, BLAKE2) of files, data, or strings. Used legitimately for integrity checking, but also in ransomware (identifying file types to target), content-addressable storage, fingerprinting systems or users, and detecting whether a file has already been processed. |
| `CRPT.CREDHASH` | Credential Hashing / Password Operations | Using password-specific hashing algorithms — bcrypt, scrypt, argon2, PBKDF2 — or comparing input against stored password hashes. Distinct from general hashing in that these algorithms are purpose-built for credential processing. In legitimate code: user authentication. In malicious code: validating backdoor passwords (`BP-BACKDOOR` Variant B), brute-force preparation, or offline credential cracking. The presence of credential hashing in code that is not an authentication system is suspicious. |
| `CRPT.SIGN` | Signing / Verification | Creating or verifying digital signatures (RSA-PSS, ECDSA, EdDSA, HMAC for message authentication). May indicate anti-tamper mechanisms, payload authentication (verifying a downloaded payload was signed by the attacker), authenticated C2 commands, or transaction signing (cryptocurrency theft). Also covers AWS SigV4, GCP service account signing, and other cloud API authentication — the LiteLLM payload embedded a complete SigV4 implementation to make authenticated calls to AWS Secrets Manager. |
| `CRPT.KEYEX` | Key Exchange / Negotiation | Diffie-Hellman, ECDH, X25519, or other key agreement protocols. Key exchange establishes a shared secret between two parties — its presence in code that is not a documented communication library means something is setting up an encrypted channel. Combined with `NETW.*`, this indicates an encrypted C2 or exfiltration channel being established dynamically rather than using a hardcoded key. |
| `CRPT.CERT` | Certificate Manipulation | Generating self-signed certificates, creating certificate signing requests, installing CA certificates into system or application trust stores, modifying certificate validation behavior (disabling verification, pinning to specific certs), or extracting private keys from certificate stores. Installing a CA certificate is MITM setup. Disabling certificate verification enables interception of HTTPS traffic. Generating certificates at runtime for undocumented purposes is suspicious. |
| `CRPT.CUSTOM` | Custom / Hand-Rolled Cryptographic Implementation | Implementing cryptographic algorithms from scratch rather than using established libraries (OpenSSL, libsodium, native crypto modules). This is one of the strongest individual signals in the category. Legitimate developers use crypto libraries — they don't implement AES, RSA, or SHA-256 by hand. Hand-rolled crypto appears in malware for specific reasons: to avoid dependencies on crypto libraries that would be flagged by analysis tools, to avoid import-based detection, to embed a complete crypto pipeline in a single self-contained payload, or to implement intentionally weakened crypto that appears secure but is breakable by the attacker. The LiteLLM collector embedded a full SigV4 signing implementation rather than importing boto3 — precisely to avoid the dependency. |

## Severity Baseline

`CRPT.CUSTOM` is high in any context — hand-rolling crypto is almost always either incompetent or deliberately evasive. `CRPT.CERT` (installing CA certs or disabling verification) is high. `CRPT.SYMENC` in non-crypto libraries is medium-high; combined with `FSYS` (encrypting files on disk) it becomes very high. `CRPT.ASYMENC` paired with a hardcoded public key is high. `CRPT.KEYEX` in non-communication code is high. `CRPT.CREDHASH` outside of authentication systems is medium-high.

## Escalation Factors

The following conditions increase the suspicion level of any `CRPT` finding:

- **`CRPT.CUSTOM` is present in any capacity.** Hand-rolled crypto is the single strongest CRPT signal. Legitimate developers do not implement AES, RSA, or key exchange from scratch — they use audited libraries. The LiteLLM attack embedded a complete RSA-4096 + AES-256-CBC pipeline plus full AWS SigV4 implementation, all hand-rolled to avoid importing `boto3` or `cryptography`. Any custom implementation warrants immediate escalation.
- **An asymmetric public key is hardcoded in source or binary.** A hardcoded attacker-controlled public key is the ransomware setup pattern: the malware encrypts a per-victim symmetric key with the attacker's public key so only the attacker can decrypt. No legitimate application hardcodes a foreign public key.
- **`CRPT.KEYEX` appears in code with no communication or protocol role.** Key exchange exists to establish a shared secret between two parties. If the surrounding code has no network socket, no TLS handshake, and no documented protocol, the key exchange is setting up a covert channel.
- **`CRPT.CERT` operations disable verification or install a new root CA.** These operations have one primary illegitimate use: intercepting traffic the application is not supposed to see. Legitimate applications almost never modify the trust store at runtime.
- **Crypto operations present with no declared crypto dependency.** If a package declares no cryptographic library in its manifest but inspection reveals AES, RSA, or key exchange operations, the implementation is either hand-rolled or smuggled in through an obscured transitive dependency.
- **`CRPT.SYMENC` or `CRPT.KEYGEN` co-located with filesystem enumeration.** Enumerating files and then generating keys is the ransomware preparation sequence. Either alone is context-dependent; together with `FSYS` access they constitute a high-confidence cluster.
- **Key or IV material derived from victim-specific runtime data.** Deriving key material from hostname, MAC address, username, or process ID produces deterministic encryption tied to a specific victim — a ransomware and C2 beacon pattern. Legitimate encryption uses random IVs and managed keys.
- **Crypto operations present only in post-install hooks or non-obvious execution paths.** Supply chain attacks hide crypto operations in lifecycle scripts or deeply nested dependencies precisely because reviewers focus on the primary package code.
- **`CRPT.HASH` or `CRPT.SIGN` used on outbound data immediately before a network call.** Hashing or signing data before exfiltration serves to verify integrity of stolen data at the receiver or implement a covert authentication scheme.
- **`CRPT.CUSTOM` combined with `OBFS.*` subtypes.** Obfuscation layered on top of hand-rolled crypto is a deliberate attempt to slow analysis. This is the highest-confidence cluster in the taxonomy.

## De-escalation Factors

The following conditions reduce — but do not eliminate — suspicion:

- **Well-known, audited library call with no customization.** A straightforward call to `cryptography.hazmat`, `libsodium`, `OpenSSL`, `BouncyCastle`, or equivalent with no monkey-patching or interception of output is the expected pattern. *(Caveat: verify the import resolves to the genuine library. Supply chain packages have impersonated `cryptography`, `pycryptodome`, and similar names.)*
- **Crypto operation is the declared, documented purpose of the package.** An encryption utility, a password manager SDK, or a TLS wrapper will legitimately contain high concentrations of CRPT subtypes. *(Caveat: when the crypto scope exceeds what the stated purpose requires — like LiteLLM's full SigV4 + RSA pipeline — treat the excess as unexplained regardless of the library's legitimacy.)*
- **`CRPT.HASH` used exclusively for integrity checking or content addressing with no key material.** Hashing a file to verify a download, generating a cache key, or producing a content-addressable identifier are low-risk uses. *(Caveat: confirm the hash output is not subsequently used as key material, an HMAC secret, or transmitted outbound.)*
- **`CRPT.CREDHASH` in a clearly scoped authentication module.** bcrypt, scrypt, and argon2 in a password storage or verification context are expected. *(Caveat: `CRPT.CREDHASH` outside auth scope — in a background worker, data export routine, or network client — does not de-escalate.)*

> **Important caveat:** Cryptography is inherently dual-use. The same AES-256-CBC call appears in a password manager and in ransomware. De-escalation based on the cryptographic operation itself is never sufficient — the context (what is being encrypted, why, and what happens to the output) determines intent.

## Common Combinations

| Combination | Suggests | Escalation |
|---|---|---|
| `CRPT.ASYMENC` + `CRPT.SYMENC` + `CRPT.KEYGEN` | Ransomware key setup — hybrid encryption with per-victim symmetric key encrypted by attacker's public key | Critical |
| `CRPT.CUSTOM` + `OBFS.BITWISE` | Hand-rolled crypto obfuscated with bitwise operations — strongest combined signal in the taxonomy | Critical |
| `CRPT.CERT` + `NETW.HTTP` | MITM enablement — installing/disabling cert verification then making network calls | High |
| `CRPT.KEYEX` + `NETW.SOCKET` or `NETW.HTTP` | Covert channel establishment — key exchange followed by network activity | High |
| `CRPT.ASYMENC` + `ARTF.CREDENTIAL` (hardcoded key) + `CRPT.SIGN` | C2 authentication — asymmetric encryption plus signing with a fixed key | High |
| `CRPT.SYMENC` + `FSYS.ENUM` + `FSYS.WRITE` | File encryption loop — enumerate files, encrypt each, write back (ransomware execution) | Critical |
| `CRPT.HASH` + `NETW.*` | Integrity-checked exfiltration — hashing data before sending for receiver verification | Medium-high |
| `CRPT.CUSTOM` + `CRPT.SIGN` | Hand-rolled signature scheme — LiteLLM's SigV4 implementation to avoid boto3 | High |
| `CRPT.KEYGEN` + `RECN.OS` or `RECN.HW` | Victim-keyed derivation — key material from machine identifiers | High |
| `CRPT.CERT` + `CRPT.CUSTOM` + `NETW.HTTP` | Full MITM stack — custom crypto plus cert manipulation plus outbound HTTP | Critical |

## Disambiguation

### CRPT.CUSTOM vs. OBFS.BITWISE

These two subtypes share significant surface area and are the most frequently confused pairing.

**`CRPT.CUSTOM`** applies when the code implements a recognizable cryptographic algorithm — AES rounds, RSA exponentiation, Diffie-Hellman parameter setup, a stream cipher — but does so from scratch rather than using a library. Key indicators: recognizable S-boxes or round constants, explicit key schedule, modular exponentiation, polynomial field arithmetic.

**`OBFS.BITWISE`** applies when bitwise operations (XOR, bit rotation, shift, mask) transform data in a way that appears designed to obscure rather than to implement a formal cipher. The structure is ad hoc; there is no identifiable algorithm specification.

The rule: if the implementation can be matched to a named algorithm specification (even a weak one like RC4), use `CRPT.CUSTOM`. If the bitwise operations follow no recognizable structure, use `OBFS.BITWISE`. When both are present — custom cipher implemented and then additionally obfuscated — tag both. The combination is the highest-confidence cluster in the taxonomy.

### CRPT.HASH vs. ARTF.HASH

**`CRPT.HASH`** applies when a hash function is invoked as part of a security-relevant operation: HMAC construction, key derivation, digital signature, integrity checking in a trust decision.

**`ARTF.HASH`** applies when a hardcoded hash value appears as a static artifact — a known-good checksum, a content identifier, a lookup key.

The practical test: `CRPT.HASH` is the operation of computing a hash. `ARTF.HASH` is the presence of a hash value in source or binary. When code computes a hash and compares it against a hardcoded value, both apply: `CRPT.HASH` for the computation, `ARTF.HASH` for the embedded comparison value.

### CRPT.SYMENC vs. OBFS.ENCRYPT

**`CRPT.SYMENC`** applies when a symmetric cipher encrypts data for a functional purpose — protecting data at rest, securing a channel, implementing a protocol. The encryption has a declared or inferable purpose.

**`OBFS.ENCRYPT`** applies when encryption conceals the code itself or its static artifacts from analysis — encrypted string literals decrypted at runtime, encrypted payload blobs decrypted and executed.

The distinction: `CRPT.SYMENC` operates on data the application processes; `OBFS.ENCRYPT` operates on the application itself or its observable strings. A ransomware payload encrypting victim files is `CRPT.SYMENC`. The same ransomware decrypting its own C2 URL at runtime is `OBFS.ENCRYPT`. Both can be present simultaneously.

### CRPT.SIGN vs. CRPT.CERT

**`CRPT.SIGN`** covers digital signature operations — signing messages, verifying signatures, HMAC construction, AWS SigV4 request signing. The operation is about authenticity of data or messages.

**`CRPT.CERT`** covers operations on X.509 certificates and the PKI trust model — loading certificates, installing root CAs, disabling verification, generating self-signed certs. The operation is about authenticity of network endpoints.

`CRPT.SIGN` at high severity requires additional context (hardcoded keys, unexplained signing). `CRPT.CERT` is high by default because the primary illegitimate use — disabling or redirecting certificate verification — has an almost immediate MITM implication.

## Investigation Questions

When a `CRPT` finding is detected, answer these questions to drive the investigation:

### For any CRPT subtype:
1. **Is there a declared cryptographic dependency in the package manifest?** Undeclared crypto operations that cannot be attributed to a manifest entry are a strong indicator of hand-rolled implementation or smuggled code.
2. **Does the scope of cryptographic operations match the package's stated purpose?** An LLM routing library implementing RSA-4096 + AES-256-CBC + SigV4 from scratch does not match its purpose. Enumerate what the package claims to do and assess whether the observed crypto is necessary.
3. **What is the key lifecycle?** Where is the key generated, stored, used, and destroyed? Key material that is transmitted outbound, persisted in cleartext, or derived from victim-specific identifiers is a significant escalation.

### For CRPT.CUSTOM specifically:
4. **Can the implementation be matched to a named algorithm specification?** Identify the algorithm. Determine whether it matches a known standard, a known weak cipher, or no recognizable scheme at all.

### For CRPT.CERT specifically:
5. **Which specific operation is performed?** Loading an existing certificate for verification, disabling verification entirely, installing a new root CA, or replacing an existing CA each have different threat models. Disabling verification and installing unauthorized CAs are highest severity.

### For CRPT.SYMENC specifically:
6. **Is the IV or nonce random, fixed, or derived?** A fixed IV breaks confidentiality for repeated plaintexts. A victim-derived IV/nonce is a red flag for intentional victim-tracking.

### For CRPT.ASYMENC specifically:
7. **Where does the public key originate?** User-provided, library-provided, or hardcoded? Hardcoded foreign public keys have one primary use — encrypting data only the key holder can read.

### Cross-cutting:
8. **Does the crypto operation precede, follow, or co-occur with a network call?** Crypto before a network call suggests data preparation for exfiltration or C2 authentication. Crypto after a network call suggests decryption of received payload.
9. **Is the crypto operation reachable from a non-interactive execution path?** Operations reachable from install hooks, import-time execution, or background threads warrant higher scrutiny than those behind explicit user action.
10. **For clusters involving `CRPT.SYMENC` + filesystem operations: what is the write pattern?** In-place overwrite of original files with encrypted content and no key recovery mechanism is the ransomware pattern.
11. **Has the implementation been tested against known vectors?** Legitimate crypto libraries ship with test suites. Hand-rolled implementations rarely do. The absence of tests informs confidence about intent.
12. **For `CRPT.KEYEX`: is there a corresponding protocol or handshake structure?** If no protocol structure is visible — no handshake, no session state, no message framing — the key exchange may be a covert channel in minimal implementation.
