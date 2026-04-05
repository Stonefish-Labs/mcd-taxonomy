# Confidence and Severity Framework

## Severity Levels

Severity reflects how suspicious an indicator is **in isolation**, before considering combinations or context.

| Level | Meaning |
|---|---|
| **Informational** | Commonly seen in legitimate software. Only meaningful in combination with other indicators. |
| **Low** | Unusual in the specific context (e.g., a utility library) but has common benign explanations. |
| **Medium** | Warrants investigation. The indicator has both malicious and benign explanations, and additional evidence is needed to determine which. |
| **High** | Rarely benign in the observed context. Should trigger active investigation. |
| **Critical** | Almost never benign. Examples: `EXEC.INJECT`, `AITM.INJECT` in a dependency, `PRST.BOOTKIT`. |

## Confidence Model

Confidence reflects certainty that a behavioral pattern is **actually present** (not a false positive), considering all available evidence.

| Level | Meaning |
|---|---|
| **Low** | Pattern partially matches. Some constituent POIs are present but required elements may be ambiguous or missing context. |
| **Medium** | All required POIs are present with plausible reachability. Supporting POIs may or may not be present. |
| **High** | All required POIs present with confirmed reachability. Multiple supporting POIs present. Contextual signals align. |

## Combination Effects

- Multiple POIs from **different categories** in the same scope are more suspicious than multiple POIs from the same category.
- **Obfuscation** (`OBFS.*`) acts as a severity **multiplier** on any co-occurring POI.
- **Evasion** (`EVSN.*`) acts as a severity **multiplier** — code that hides from analysis is assumed to have something worth hiding.
- **Contextual signals** modify confidence, not severity: they change how certain we are, not how bad it would be if true.
