# POI Expansion Tracker

Tracks progress on expanding each POI category with operational guidance sections (escalation factors, de-escalation factors, common combinations, disambiguation, investigation questions).

Reference implementation: [OBFS](pois/OBFS/README.md)

## Status

| POI ID | Name | Status | Notes |
|---|---|---|---|
| ARTF | Hardcoded Artifacts | **Complete** | 6+10 escalation factors, 4 de-escalation, 10 combinations, 5 disambiguations, 15 questions |
| NETW | Network Communication | **Complete** | 10 escalation, 5 de-escalation, 14 combinations, 5 disambiguations, 13 questions |
| FSYS | Filesystem Operations | **Complete** | 10 escalation, 5 de-escalation, 10 combinations, 4 disambiguations, 12 questions |
| EXEC | Code Execution | **Complete** | 9 escalation, 4 de-escalation, 10 combinations, 5 disambiguations, 12 questions |
| LOAD | Dynamic Code Loading | **Complete** | 10 escalation, 5 de-escalation, 10 combinations, 5 disambiguations, 12 questions |
| OBFS | Obfuscation | **Complete** | Reference implementation — 8 escalation, 5 de-escalation, 9 combinations, 5 disambiguation, 11 questions |
| EVSN | Evasion and Anti-Analysis | **Complete** | 10 escalation, 5 de-escalation, 9 combinations, 5 disambiguations, 11 questions |
| CRED | Credential and Secret Access | **Complete** | 10 escalation, 4 de-escalation, 10 combinations, 5 disambiguations, 12 questions |
| PRST | Persistence | **Complete** | 8 escalation, 3 de-escalation, 9 combinations, 3 disambiguations, 10 questions |
| PRIV | Privilege Escalation | **Complete** | 7 escalation, 3 de-escalation, 7 combinations, 3 disambiguations, 8 questions |
| RECN | System Reconnaissance | **Complete** | 8 escalation, 4 de-escalation, 9 combinations, 4 disambiguations, 10 questions |
| TIME | Temporal Operations | **Complete** | 6 escalation, 4 de-escalation, 7 combinations, 3 disambiguations, 8 questions |
| PKGM | Package and Build Manipulation | **Complete** | 10 escalation, 5 de-escalation, 10 combinations, 4 disambiguations, 13 questions |
| CRPT | Cryptographic Operations | **Complete** | 10 escalation, 4 de-escalation, 10 combinations, 4 disambiguations, 12 questions |
| AITM | AI-Targeted Manipulation | **Complete** | 8 escalation, 3 de-escalation, 8 combinations, 3 disambiguations, 10 questions |
| RSRC | Resource Manipulation | **Complete** | 6 escalation, 3 de-escalation, 7 combinations, 3 disambiguations, 8 questions |

## Summary

All 16 POI categories have been expanded with operational guidance sections. The expansion follows the OBFS reference implementation format and covers:

- **Escalation Factors:** Specific, actionable conditions that increase suspicion (6-10 per POI)
- **De-escalation Factors:** Conditions that reduce but do not eliminate suspicion, with caveats (3-5 per POI)
- **Common Combinations:** Tables showing how each POI combines with others (7-14 per POI)
- **Disambiguation:** Clarification of overlapping or confusing classifications (3-5 per POI)
- **Investigation Questions:** Structured questions for triage, organized general-then-subtype-specific (8-15 per POI)
