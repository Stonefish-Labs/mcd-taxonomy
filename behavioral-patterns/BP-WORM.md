# BP-WORM — Worm / Propagation

## Description

Code that replicates itself to other systems or repositories without user initiation. Worms spread by exploiting vulnerabilities, abusing trust relationships (SSH keys, shared credentials), or leveraging access to package registries to publish copies of themselves.

## Constituent POIs

| Role | POI | Notes |
|---|---|---|
| **Required** | `RECN.NET` | Discovering propagation targets |
| **Required** | `NETW.*` | Communicating with targets |
| **Required** | `EXEC.*` or `FSYS.WRITE` | Delivering the payload to targets |
| Supporting | `CRED.SSH` | Using stolen SSH keys for lateral movement |
| Supporting | `PKGM.*` | Publishing malicious packages to registries |
| Supporting | `RECN.SW` | Identifying vulnerable software on targets |

## Real-World Analogue

The Morris Worm (1988). WannaCry's SMB propagation. Modern supply chain worms that compromise a package and push malicious updates to all consumers.

## Investigation Guidance

- **Verify:** What is the propagation mechanism? What systems or registries are targeted? Is the payload self-replicating or a one-shot delivery?
- **Escalates:** Automated discovery and exploitation. Use of stolen credentials for lateral movement. Publication to package registries.
- **De-escalates:** Network scanning is a documented feature (e.g., a network discovery tool). File copying is within a documented deployment scope.
