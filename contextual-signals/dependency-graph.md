# Dependency Graph Signals

| Signal | Description | Effect |
|---|---|---|
| **New dependency in patch release** | A patch version (x.y.Z) introduces a new dependency that was not present in the previous version | High signal — patches fix bugs, they do not add dependencies |
| **Transitive dependency anomaly** | A deep transitive dependency changes in a way that does not match the direct dependency's changelog | Suggests supply chain compromise at a lower level |
| **Dependency on unpopular package** | Depending on a very low-download, recently published package | The dependency itself may be the attack vector |
| **Circular or self-referential dependencies** | Unusual dependency structures that are not typical of legitimate packages | May indicate dependency confusion or metadata manipulation |
