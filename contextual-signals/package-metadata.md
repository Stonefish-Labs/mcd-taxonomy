# Package Metadata Signals

| Signal | Description | Effect |
|---|---|---|
| **New package** | Package was published recently with no track record | Elevates severity of any detected POIs |
| **New maintainer** | Package ownership transferred recently or a new maintainer was added shortly before a suspicious release | Elevates severity; mirrors XZ Utils attack pattern |
| **Download anomaly** | Download count inconsistent with package age or stated purpose (very low for a claimed utility, sudden spike) | Suggests either typosquatting or compromise |
| **Version gap** | Published versions skip numbers or show irregular patterns (v1.0.0 to v1.0.5 with no intermediate versions) | May indicate yanked malicious versions |
| **Metadata mismatch** | Package description, README, or documentation does not match actual code functionality | Suggests deception |
| **Provenance attestation downgrade** | A package that previously published via OIDC Trusted Publisher, Sigstore, or other verified CI/CD provenance suddenly publishes without attestation — manual token, no `gitHead`, no CI binding. The Axios compromise was detectable by this signal alone: every legitimate 1.x release was published via GitHub Actions OIDC, while the malicious 1.14.1 was published manually with a stolen npm token and had no `trustedPublisher` field or `gitHead`. Legitimate maintainers don't abandon provenance; attackers using stolen tokens can't produce it. | Very high signal — one of the strongest single indicators of account compromise |
