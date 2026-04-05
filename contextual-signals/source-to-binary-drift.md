# Source-to-Binary Drift

| Signal | Description | Effect |
|---|---|---|
| **Behavioral drift** | Compiled binary contains functionality (imports, strings, behaviors) not present in the published source | Very high signal — the binary was not built from the published source |
| **Build irreproducibility** | Binary cannot be reproduced from the published source and build instructions | May indicate post-build injection of malicious code |
| **Unexpected native extensions** | Package includes native binaries that are not explained by the package's functionality | Native code is opaque to source analysis and may contain hidden payloads |
