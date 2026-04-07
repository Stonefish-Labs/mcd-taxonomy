# BP-MITM — Traffic Interception / Man-in-the-Middle Setup

## Description

Code that positions itself to intercept, inspect, modify, or redirect network traffic between a victim and legitimate services. Unlike `BP-BACKDOOR` (which provides the attacker direct access to the host) or `BP-EXFIL` (which collects data from the host and transmits it out), `BP-MITM` operates on traffic *passing through* the compromised host — intercepting communications between the user and external services so that credentials, session tokens, API keys, and sensitive data flowing through the connection are visible to the attacker.

MITM setup typically involves two coordinated actions: **degrading the trust model** (installing a rogue CA certificate, disabling TLS verification, or downgrading protocol security) and **redirecting traffic** (configuring a local proxy, modifying DNS resolution, or setting up a transparent intercept listener). Either action alone is suspicious; together they form a complete interception capability.

The interception can be **passive** (recording traffic without modification — credential harvesting, session token capture) or **active** (modifying traffic in transit — injecting malicious content into responses, replacing downloaded binaries, altering API responses). Active interception is harder to detect because the user sees apparently normal responses.

This pattern is particularly dangerous in supply chain contexts because a dependency that installs a CA certificate and configures proxy settings gains the ability to intercept *all* HTTPS traffic from the compromised host — not just traffic related to the dependency's stated purpose.

## Constituent POIs

| Role | POI | Notes |
|---|---|---|
| **Required (one or more)** | `CRPT.CERT` | Trust store manipulation: installing a CA certificate, disabling TLS certificate validation, or replacing certificate verification callbacks with permissive stubs |
| **Required (one or more)** | `EVSN.SECDISABLE` | Weakening network security controls: modifying firewall rules to allow interception traffic, disabling HSTS, or modifying proxy auto-configuration |
| Supporting (strong) | `NETW.LISTEN` | Local proxy or transparent interceptor — a listener that accepts connections and forwards them (potentially modified) to the real destination |
| Supporting (strong) | `CRPT.KEYGEN` | Generating interception certificates on-the-fly — a CA certificate is installed, then per-domain certificates are generated dynamically to intercept individual HTTPS connections |
| Supporting (strong) | `CRPT.CUSTOM` | Custom TLS handling or certificate generation that avoids importing standard crypto libraries (to evade dependency-based detection) |
| Supporting | `PRST.*` | Persistent interception — the proxy or certificate survives reboot, creating a durable MITM position |
| Supporting | `EVSN.MASQ` | Proxy process or certificate named to resemble a legitimate system component (e.g., a CA cert named after a real vendor) |
| Supporting | `ARTF.IP` or `ARTF.DOMAIN` | Hardcoded proxy destination or interception relay server |
| Supporting | `FSYS.WRITE` | Writing proxy auto-configuration (PAC) files, modifying `/etc/hosts`, or writing system proxy settings |
| Supporting | `RECN.NET` | Network reconnaissance to identify target traffic or proxy configuration before interception setup |
| Supporting | `OBFS.*` | Concealing the interception infrastructure from code review |

## Real-World Analogue

Corporate SSL inspection appliances (legitimate, with documented deployment) use the same technical mechanism: install a trusted CA certificate, then generate per-domain certificates to decrypt and inspect HTTPS traffic. The technique is identical when weaponized — the difference is authorization and disclosure.

Malicious browser extensions that inject their own CA certificates to intercept banking traffic. Adware that installs proxy certificates to inject advertisements into HTTPS pages (Superfish/Lenovo 2015 — a pre-installed CA certificate with a trivially extractable private key enabled any attacker to intercept any affected laptop's HTTPS traffic). Supply chain packages that disable certificate verification before making network calls, enabling traffic interception by any network-positioned attacker without the package itself running a proxy.

The most subtle variant disables certificate verification *without* installing a proxy — this does not intercept traffic itself, but removes the protection that prevents a network-positioned attacker from doing so. It converts every HTTPS connection into a de facto HTTP connection from a security perspective.

## Investigation Guidance

- **Verify:** What specific certificate or trust store operation is performed? Is a new CA certificate installed into the system or user trust store? Is TLS verification disabled globally or for specific connections? Is a proxy listener established?
- **Verify:** What is the scope of the interception? System-wide (system trust store, system proxy settings) vs. application-scoped (requests library session, browser profile). System-wide interception affects all applications on the host and is categorically more severe.
- **Verify:** Is the CA certificate's private key embedded in the package, stored locally, or held remotely? An embedded private key means anyone who reads the source can intercept traffic from any affected host (the Superfish pattern). A remotely-held key limits interception to the attacker.
- **Verify:** Is the proxy or interception mechanism transparent (no explicit configuration required) or does it require traffic to be directed to it? Transparent interception via firewall redirection rules or system proxy settings is more dangerous because it captures traffic without application awareness.
- **Escalates:** CA certificate installed into the *system* trust store (affects all applications, not just the current process). Private key for the installed CA is extractable. Proxy auto-configuration (PAC) files written to system locations. Interception combined with persistence (`PRST.*`) — durable MITM position. Certificate or proxy named to resemble a legitimate vendor component (`EVSN.MASQ`). Interception targets specific high-value domains (banking, cloud provider consoles, package registries).
- **De-escalates:** Certificate operation is scoped to the package's own HTTPS client for a documented purpose (e.g., a corporate proxy client that installs its own CA for documented internal traffic routing). TLS verification is disabled only for a specific test or development endpoint, gated behind an explicit opt-in flag, and documented. The package is a documented network debugging/inspection tool (mitmproxy, Charles Proxy, Fiddler) whose stated purpose is traffic interception. *(Caveat: verify the package is the genuine tool and not a typosquat or trojanized fork.)*
