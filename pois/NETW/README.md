# NETW — Network Communication

**Applies to:** Source and binary.

## Description

Any mechanism by which code sends data to, or receives data from, an external system over a network. Network communication is the primary channel through which stolen data leaves a system, secondary payloads arrive, and command-and-control instructions are received. In libraries and packages that do not have documented network functionality, any network communication is a significant finding.

## Subtypes

| Subtype ID | Name | Description |
|---|---|---|
| `NETW.HTTP` | HTTP/HTTPS Requests | Outbound web requests. The most common communication channel for modern malware due to ubiquitous firewall allowlisting. |
| `NETW.DNS` | DNS Operations | Direct DNS queries or DNS-based data channels. DNS tunneling (encoding data in DNS queries) is a well-known exfiltration technique that bypasses most network monitoring. |
| `NETW.SOCKET` | Raw Socket Operations | Direct TCP/UDP socket creation and use. Lower-level than HTTP, harder to inspect, and a hallmark of custom C2 protocols. |
| `NETW.LISTEN` | Network Listener | Binding to a port and accepting inbound connections. A core component of backdoor functionality. |
| `NETW.IPC` | Inter-Process Communication | Named pipes, Unix domain sockets, shared memory, or other local IPC mechanisms. Can be used for communication between a malicious payload and a co-deployed component. |
| `NETW.EMAIL` | Email Transmission | Sending email programmatically via SMTP or API. A classic exfiltration channel, especially in environments where HTTP is monitored but email is not. |
| `NETW.FTP` | FTP/SFTP/SCP | File transfer protocol operations. Used for both payload retrieval and data exfiltration. |
| `NETW.WEBHOOK` | Webhook / Messaging API | Communication via Discord webhooks, Telegram bots, Slack incoming webhooks, or similar messaging APIs. Increasingly common as lightweight C2 and exfiltration channels because the traffic looks like normal app usage. |
| `NETW.WS` | WebSocket Communication | Persistent, bidirectional communication channels over the WebSocket protocol (`ws://`, `wss://`). WebSockets start as an HTTP upgrade handshake but then maintain a long-lived full-duplex connection — ideal for real-time C2 because commands and responses flow continuously without repeated HTTP request overhead. Many network monitoring tools treat the initial upgrade as a normal HTTP request and stop inspecting after the handshake, creating a blind spot. |
| `NETW.GRPC` | gRPC / Binary RPC Protocols | Communication via gRPC, Protocol Buffers, Thrift, or other binary-serialized RPC frameworks over HTTP/2. Binary serialization makes traffic opaque to text-based inspection tools and WAFs. In cloud-native environments, gRPC traffic blends seamlessly into legitimate microservice-to-microservice communication, making C2 or exfiltration channels difficult to distinguish from normal operations. |
| `NETW.BROKER` | Message Broker / Pub-Sub | Communication via message brokers and pub/sub protocols: MQTT, AMQP (RabbitMQ), Apache Kafka, Redis pub/sub, AWS SQS/SNS, or similar message queuing systems. These are inherently asynchronous and decoupled — the sender and receiver never communicate directly, making traffic analysis and attribution harder. A C2 channel over an MQTT broker looks identical to IoT device telemetry. A data exfiltration stream to a Kafka topic looks like normal event logging. |
| `NETW.SSE` | Server-Sent Events | One-way persistent HTTP streaming via Server-Sent Events. Lighter than WebSockets but still maintains a long-lived connection for receiving commands or configuration updates from a server. Increasingly common in legitimate applications (AI streaming responses, live dashboards), which provides natural cover for a C2 instruction stream. |
| `NETW.DECENTRAL` | Decentralized / Blockchain Communication | Communication via blockchain networks, decentralized storage (IPFS), smart contracts, or decentralized compute platforms (Internet Computer Protocol canisters, Ethereum contracts, Solana programs). These channels are qualitatively different from traditional network communication because they **cannot be taken down** by domain registrars, hosting providers, or law enforcement takedown requests. A C2 dead-drop hosted on an ICP canister or data encoded in blockchain transactions persists as long as the network exists. The TeamPCP campaign's CanisterWorm used an ICP canister as C2 — the first documented use of ICP for command and control. |

## Severity Baseline

`NETW.LISTEN` and `NETW.SOCKET` are high in most dependency contexts. `NETW.DECENTRAL` is high in any context — legitimate use of blockchain communication in non-blockchain packages is rare. `NETW.WS` is medium-high in dependency/library context where persistent connections are unexpected. `NETW.GRPC` and `NETW.BROKER` severity depends on whether the package has documented microservice or messaging functionality. `NETW.HTTP` severity depends heavily on what is being sent and where.

## Escalation Factors

The following conditions increase the suspicion level of any `NETW` finding:

- **The package has no documented network functionality.** Any network communication in a utility, parser, formatter, or data-processing library is anomalous by definition. The package's stated purpose is the primary context for severity.
- **The destination is not recognized infrastructure.** The target endpoint is a personal domain, a recently registered domain, a dynamic DNS hostname (e.g., `*.duckdns.org`, `*.ngrok.io`), or resolves to a residential IP block or bulletproof hosting provider. Contrast with legitimate telemetry contacting known vendor infrastructure.
- **The destination mimics a trusted service.** The Axios compromise used endpoints styled to resemble npm registry traffic (`packages.npm.org/` prefix). Typosquatted hostnames, attacker-controlled subdomains, and URL paths echoing legitimate API patterns are all escalating signals.
- **Data sent includes secrets, credentials, or environment variables.** Any combination of `NETW` with credential access (`CRED.*`), environment variable reads, or filesystem reads of known secret locations is a strong escalation. The LiteLLM attack combined `NETW.HTTP` with credential reads targeting AWS infrastructure.
- **Communication is triggered at install, import, or startup — not at explicit runtime use.** Network calls embedded in package lifecycle hooks (`postinstall`, `__init__.py` module-level execution, static initializers) execute before the user has invoked any functionality. There is very limited legitimate justification for install-time network calls.
- **Traffic is encoded, encrypted with a hardcoded key, or uses non-standard framing.** Base64-encoded POST bodies, custom binary framing over raw sockets, or DNS queries encoding data in subdomains all indicate deliberate concealment of payload content.
- **A decentralized or censorship-resistant channel is used.** `NETW.DECENTRAL` has no legitimate use case in a standard software library or package. ICP canisters, IPFS content identifiers, and smart contract interactions cannot be blocked by conventional network controls and are high severity in any context.
- **Communication occurs on non-standard ports or uses protocol mismatches.** HTTP traffic on unusual ports, DNS over non-standard resolvers, or SMTP from code with no mail functionality.
- **A listener binds to `0.0.0.0` or an externally routable interface.** `NETW.LISTEN` on an external interface in a library package is a core backdoor pattern, substantially more severe than a localhost listener.
- **The channel is persistent or polling.** WebSocket connections, SSE streams, or HTTP long-poll loops that remain open after the triggering operation completes suggest waiting for inbound instructions — the defining characteristic of a C2 channel.

## De-escalation Factors

The following conditions reduce — but do not eliminate — suspicion:

- **The destination is documented vendor telemetry infrastructure with a known opt-out mechanism.** Crash reporters, update checkers, and analytics endpoints contacting named vendor infrastructure (e.g., Sentry ingest endpoints, documented telemetry domains) are routine. They still warrant disclosure review but are not malware indicators.
- **Communication occurs only when the user explicitly invokes a network-facing feature.** An HTTP client library calling out when `client.get()` is invoked is expected behavior. The call must be causally downstream of explicit user action, not of import or initialization.
- **The payload is fully observable, documented, and does not include system data.** A health-check ping that sends a static version string with no host identifiers, credentials, or environment context is low risk. Observability is a prerequisite for de-escalation: if you cannot easily read the payload, you cannot de-escalate.
- **IPC channel is local-only and part of a documented plugin or service architecture.** `NETW.IPC` over a Unix domain socket in a process orchestrator or IDE plugin that documents its IPC interface is expected behavior. Confirm the socket path is non-guessable and that no external routable network interface is involved.
- **Traffic pattern matches the package's stated purpose exactly.** An API client package that makes `NETW.HTTP` calls to the API it wraps, using user-supplied credentials passed at call time, is doing exactly what it should. The destination, payload structure, and triggering condition should all be consistent with the documented interface.

> **Important caveat:** De-escalation based on documented purpose applies only when the network behavior is fully consistent with that purpose. A legitimate HTTP client library that also makes undocumented calls to an unrelated endpoint is not de-escalated by the presence of legitimate calls. Verify the specific finding, not the package in general.

## Common Combinations

| Combination | Suggests | Escalation |
|---|---|---|
| `NETW.HTTP` + `CRED.*` | Credential exfiltration via HTTP — the canonical supply chain theft chain | Very high — matches both Axios npm and LiteLLM PyPI patterns |
| `NETW.WEBHOOK` + `CRED.*` | Credentials POSTed to Discord/Telegram/Slack webhook | Very high — attacker owns receiving infrastructure with no personal hosting |
| `NETW.HTTP` + `OBFS.*` | Hidden HTTP C2 — encoded POST bodies, dynamic URL construction | High — concealment of payload content or destination |
| `NETW.DNS` + `OBFS.*` | DNS tunneling — data encoded into query subdomains or TXT payloads | High — low-bandwidth exfiltration that often bypasses egress filtering |
| `NETW.SOCKET` + `EXEC.*` | Reverse shell — raw socket with stdin/stdout redirected to shell | Very high — classic remote access payload |
| `NETW.LISTEN` + `EXEC.*` | Bind shell / backdoor — port listener that spawns a shell on connection | Very high — core backdoor pattern |
| `NETW.DECENTRAL` + `EXEC.*` | Uncensorable C2 — commands retrieved from blockchain/ICP/IPFS | Very high — cannot be blocked by domain takedown or IP blocking |
| `NETW.WS` + `EXEC.*` | WebSocket C2 — persistent bidirectional channel for command execution | Very high — real-time C2 without polling artifacts |
| `NETW.*` + `PKGM.INSTALL` | Network call during package installation | Very high — install-time network access is almost never legitimate |
| `NETW.*` + `PRST.*` | Network channel combined with persistence | Very high — durable C2; implant survives reboot |
| `NETW.*` + `OBFS.*` + `CRED.*` | Full exfiltration kill chain — collection, concealment, transmission | Very high — treat as confirmed malicious pending investigation |
| `NETW.LISTEN` + `FSYS.*` | File server backdoor — listener serves filesystem contents on demand | High — enables attacker-directed exfiltration without persistent outbound connection |
| `NETW.EMAIL` + `CRED.*` | Credential exfiltration via email | High — SMTP exfiltration in environments where HTTP is monitored |
| `NETW.BROKER` + `EXEC.*` | Pub-sub C2 — commands via MQTT/AMQP/Redis channel | High — asynchronous, decoupled; broker intermediary complicates attribution |

## Disambiguation

### NETW.IPC vs. NETW.SOCKET

The critical distinction is locality. `NETW.IPC` covers communication mechanisms constrained to the local host: Unix domain sockets, named pipes, shared memory segments, D-Bus. `NETW.SOCKET` covers TCP and UDP sockets bound to a network interface, including loopback when the socket is created with `AF_INET` rather than `AF_UNIX`. The severity gap is significant: `NETW.IPC` in a process-orchestration or plugin context is often expected; `NETW.SOCKET` in the same context is anomalous. Check the socket family, the bind/connect address, and whether a named pipe path is under a world-writable directory.

### NETW.HTTP vs. NETW.WEBHOOK vs. NETW.WS

All three use HTTP as the underlying transport. `NETW.HTTP` is the residual category for standard request-response calls to arbitrary endpoints. `NETW.WEBHOOK` applies specifically when the destination is a messaging platform webhook URL (Discord, Telegram, Slack) — the significance being that the attacker owns the receiving infrastructure without operating their own server. `NETW.WS` applies when the connection is upgraded to WebSocket and maintained as a persistent, bidirectional channel. A single HTTP POST to a Discord webhook URL is `NETW.WEBHOOK`, not `NETW.HTTP`.

### NETW.DNS vs. standard resolution

Standard DNS resolution performed by the OS resolver is not a NETW finding — it is infrastructure. `NETW.DNS` applies to code that constructs DNS queries programmatically, uses a hardcoded or non-system resolver, or encodes data into query subdomains or record payloads. DNS-over-HTTPS (DoH) to a hardcoded resolver should be classified as both `NETW.DNS` and `NETW.HTTP`.

### NETW.GRPC vs. NETW.SOCKET

gRPC uses HTTP/2 as its transport and is distinct from raw socket operations. `NETW.GRPC` applies to code using gRPC libraries or binary-serialized RPC frameworks. The significance is that payload content is opaque to text-based inspection tools. If code constructs raw TCP frames that resemble a binary protocol without using a recognized RPC library, classify as `NETW.SOCKET`.

### NETW.LISTEN: Localhost vs. External Interface

Always record the bind address. Localhost listeners in development tools, local proxies, and plugin hosts have plausible legitimate purpose. Listeners on `0.0.0.0` or specific external interfaces in a library package do not. The bind address is the primary discriminator between "local service" and "backdoor."

## Investigation Questions

When a `NETW` finding is detected, answer these questions to drive the investigation:

### For any NETW subtype:
1. **Does the package's documentation or stated purpose include network functionality?** If no, why does this code make network calls?
2. **When is the network call triggered?** Install time, import/module load, first use of any function, or only when the user explicitly invokes a network-facing feature? Earlier in the lifecycle is higher severity.
3. **What data is included in the outbound payload?** Can the full payload be reconstructed statically, or does it require dynamic analysis? Does it include credentials, environment variables, or system identifiers?
4. **Who owns the destination endpoint?** Is the domain hardcoded, dynamically constructed, or user-supplied? What is the domain registration date and registrar? Does it share infrastructure with known malicious actors?
5. **Is there an inbound component?** Does the code receive and act on data returned from the network call? If so, what happens to the received data — is it executed, written to disk, or passed to a deserializer?

### For NETW.HTTP specifically:
6. **Does the HTTP request include headers or URL structures that mimic a trusted service?** The Axios compromise used traffic patterns resembling npm registry requests. Check for deliberate mimicry of legitimate traffic.
7. **Is TLS certificate validation disabled?** Skipping certificate verification disables the primary protection against interception and is an escalating signal.

### For NETW.DNS specifically:
8. **Does the code use the system resolver or a hardcoded alternative?** A hardcoded resolver IP bypasses system DNS monitoring.
9. **Are hostnames or query parameters constructed by encoding data into subdomain labels?** Extract and decode any such construction to determine payload content.

### For NETW.SOCKET specifically:
10. **After the socket is established, is there a loop reading from the socket and passing data to an execution function?** This is the reverse shell pattern.

### For NETW.LISTEN specifically:
11. **What interface does the listener bind to?** `0.0.0.0` vs. loopback. What happens to accepted connections — are they handed to a shell, a file server, or a command dispatcher?

### For NETW.WEBHOOK specifically:
12. **What platform is the webhook for, and can the webhook URL be inspected?** The URL itself is evidence of attacker infrastructure. Identify the platform and, where APIs allow, check creation date or report status.

### For NETW.DECENTRAL specifically:
13. **What is the specific decentralized address, canister ID, contract address, or IPFS CID?** Decentralized infrastructure cannot be taken down — document the identifier in full as permanent evidence regardless of investigation outcome.
