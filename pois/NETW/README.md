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
