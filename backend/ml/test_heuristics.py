import sys, os
sys.path.insert(0, "/app")
from app.services.ml_classifier import classify

tests = [
    ([0.0, 0.0, 0.0, 0.0, 0.5, 0.0, 0.0], 30,  "auth_failure=0.5 only (empty body PayPal)"),
    ([0.0, 0.0, 0.0, 1.0, 0.5, 0.0, 0.0], 60,  "impersonation=1.0 + auth=0.5"),
    ([0.8, 0.6, 0.0, 0.9, 1.0, 0.3, 0.0], 65,  "PayPal sim: urgency+credential+impersonation+auth"),
    ([1.0, 1.0, 0.0, 1.0, 1.0, 0.3, 0.0], 80,  "full phishing vector"),
    ([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], 0,   "clean email -- all zeros"),
    ([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0], 80,  "known_bad_url only"),
]

all_pass = True
for vector, min_expected, label in tests:
    r = classify(vector)
    score = r["risk_score"]
    passed = (score >= min_expected) if min_expected > 0 else (score == 0)
    status = "PASS" if passed else "FAIL"
    if not passed:
        all_pass = False
    op = ">=" if min_expected > 0 else "=="
    print("%s  score=%-3d  expect%s%d  [%s]" % (status, score, op, min_expected, label))

print()
print("ALL PASS" if all_pass else "SOME TESTS FAILED")
