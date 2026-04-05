# BP-RANSOM — Ransomware

## Description

Code that encrypts files on the local filesystem and demands payment for decryption. The pattern is distinctive: enumerate files, encrypt them with a key the attacker controls, destroy or encrypt the local key, and present a ransom demand.

## Constituent POIs

| Role | POI | Notes |
|---|---|---|
| **Required** | `FSYS.ENUM` | Discovering files to encrypt |
| **Required** | `CRPT.SYMENC` | Encrypting file contents |
| **Required** | `FSYS.WRITE` | Writing encrypted files back (or replacing originals) |
| Supporting | `CRPT.ASYMENC` | Encrypting the symmetric key with attacker's public key |
| Supporting | `ARTF.CRYPTO_ADDR` | Cryptocurrency address for ransom payment |
| Supporting | `FSYS.DELETE` | Deleting original unencrypted files |
| Supporting | `NETW.*` | Communicating with C2 or transmitting decryption key |
| Supporting | `PRIV.*` | Escalating privileges to access more files |

## Real-World Analogue

WannaCry, NotPetya, REvil. Ransomware remains one of the most financially impactful malware categories.

## Investigation Guidance

- **Verify:** What files are being enumerated? Is the encryption using a hardcoded key or generating a new one? Is there a ransom note or payment address?
- **Escalates:** Asymmetric encryption of the symmetric key (indicates no self-recovery). Cryptocurrency address present. Shadow copy deletion or backup targeting.
- **De-escalates:** Encryption is applied to the package's own data files. Encryption key is derived from user input (could be a legitimate encryption tool).
