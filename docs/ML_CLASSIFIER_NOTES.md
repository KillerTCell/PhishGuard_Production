# PhishGuard — ML Classifier Notes & Known Limitations

## Architecture
Two-layer scoring system:
1. Random Forest classifier (primary, ML-based) — outputs phishing probability 0–100
2. Heuristic override rules (safety net) — floor values for obvious cases the RF under-scores

## Random Forest Configuration
- n_estimators: 200
- class_weight: balanced
- min_samples_leaf: 2
- max_features: sqrt
- n_jobs: -1
- random_state: 42
- Training data: 1000 phishing + 1000 safe + 400 suspicious (5 patterns each for phishing/safe, 2 for suspicious)

## Feature Vector Order (FIXED — never change without retraining)
| Index | Feature | Extractor |
|---|---|---|
| 0 | urgency_language | spaCy PhraseMatcher, 28 patterns |
| 1 | credential_request | spaCy PhraseMatcher, 22 patterns |
| 2 | link_mismatch | tldextract domain comparison |
| 3 | impersonation_language | spaCy PhraseMatcher + sender domain analysis |
| 4 | auth_failure | SPF/DKIM/DMARC results |
| 5 | grammar_quality | TextBlob correction ratio |
| 6 | known_bad_url | PhishTank async lookup (Redis-cached 24h) |

## Sender Domain Impersonation Detection
Feature 3 (`impersonation_language`) checks TWO sources:

1. **Body text** — spaCy PhraseMatcher for 26 brand+action phrases ("paypal account", "microsoft security", etc.)
2. **Sender domain** — keyword matching against `_SENDER_BRAND_KEYWORDS` dict (17 brands including typo variants like "paypa" → PayPal) against `_BRAND_CANONICAL_DOMAINS`

Sender-domain hits count as 2 match events (heavier weight than body-text hits) because the sender address is the strongest impersonation signal when the email body is empty or sparse.

This catches typosquatted domains like `paypa1-secure.com`, `paypa1-secure.net` that body-text analysis misses entirely.

## Heuristic Override Rules
Applied AFTER the Random Forest to catch obvious phishing the model under-scores. These are safety-net floors, not replacements for the ML model.

| Condition | Minimum Risk Score | Classification at default thresholds |
|---|---|---|
| auth_failure >= 0.5 | 30 | suspicious |
| auth_failure >= 0.5 AND impersonation >= 0.5 | 60 | suspicious |
| auth_failure >= 1.0 AND impersonation >= 0.5 | 65 | suspicious |
| link_mismatch >= 0.5 AND auth_failure >= 0.5 AND urgency >= 0.5 | 70 | suspicious |
| auth_failure >= 1.0 AND urgency >= 0.5 AND credential >= 0.5 | 75 | suspicious |
| known_bad_url >= 1.0 | 80 | phishing |
| credential >= 0.5 AND impersonation >= 0.5 AND auth_failure >= 0.5 | 85 | phishing |

## Organisation Thresholds (Default)
- suspicious_threshold: 30
- phishing_threshold: 80

## Known Issue: TextBlob MissingCorpusError
The `grammar_quality` extractor uses TextBlob which requires NLTK corpora (`punkt`, `averaged_perceptron_tagger`) not included in the Docker image. TextBlob raises `MissingCorpusError` and the feature is skipped (fail-open). The pipeline continues with 6/7 features, scoring grammar_quality=0.0. This is non-critical; the heuristic overrides compensate for zero-body emails.

**Fix**: Add `RUN python -m textblob.download_corpora` to the Dockerfile builder stage.

## The Empty-Body Problem
Emails pasted via the UI without a body (or with body=NULL in DB) score:
- urgency=0, credential=0, link_mismatch=0, impersonation=0 (body-text-based)
- auth_failure=0.5 (if SPF/DKIM/DMARC all absent)
- The RF then gives phishing_prob≈0 → risk_score=0

**Resolved by**: sender domain impersonation detection (raises impersonation score) + heuristic override (auth_failure=0.5 → minimum 30).

## Retraining

```bash
cd backend
docker compose exec api python ml/train.py
docker cp backend-api-1:/app/ml/model.pkl ml/model.pkl
docker cp backend-api-1:/app/ml/test_data.pkl ml/test_data.pkl
docker cp backend-api-1:/app/ml/metrics.json ml/metrics.json
docker cp ml/model.pkl backend-worker-1:/app/ml/model.pkl
docker compose restart worker
```

After retraining, verify with:
```bash
docker cp ml/test_heuristics.py backend-api-1:/app/ml/test_heuristics.py
docker compose exec api python ml/test_heuristics.py
```

## Re-analysing Existing Emails
After code or model changes, re-run the full pipeline for specific emails:

```bash
docker cp ml/reanalyze.py backend-api-1:/app/ml/reanalyze.py
docker compose exec api python ml/reanalyze.py
```

Edit `reanalyze.py` to include the target email UUIDs.
