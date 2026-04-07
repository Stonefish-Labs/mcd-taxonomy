# Contextual Signals

Contextual signals are observations about the ecosystem, metadata, and provenance of an artifact that are not detectable within the code itself. They do not generate findings independently — they modify confidence in findings from POIs and behavioral patterns. A medium-confidence finding in a package with multiple adverse contextual signals should be treated as high-confidence.

These signals are **supporting evidence** that feeds into the confidence model, not a separate detection tier.

## Signal Categories

| Category | Description |
|---|---|
| [Package Metadata](package-metadata.md) | Publication history, maintainer changes, download anomalies, provenance |
| [Dependency Graph](dependency-graph.md) | New dependencies in patches, transitive anomalies, unpopular dependencies |
| [Source-to-Binary Drift](source-to-binary-drift.md) | Behavioral drift, build irreproducibility, unexpected native extensions |
| [Temporal Signals](temporal-signals.md) | Abandonment patterns, coordinated publication, pre-staged versions |
| [Execution Context](execution-context.md) | CI/CD targeting, security tooling context, privileged orchestration |
| [Network Destination](network-destination.md) | Jurisdictional risk, bulletproof hosting, recently registered domains, dynamic DNS |
