import sys
sys.path.insert(0, "/app")

from app.tasks.analysis_tasks import extract_features, classify_email, generate_explanation

email_ids = [
    "a0c9732e-590e-4f38-b692-0a607a9f4a37",
    "7943318a-5242-47d3-9151-6ae5fe613cfa",
    "3b8116a0-6cb0-4e8c-b199-113f607cebac",
    "1077b920-64d7-4553-be3b-34e803cdb07e",
    "dcf02eee-17f4-43fb-890b-1a540b9083bf",
    "6eedfd94-efb8-44b6-9758-943957707f62",
]

for eid in email_ids:
    print("Re-analysing %s ..." % eid)
    # Chain: re-extract features -> re-classify -> regenerate explanation
    extract_features.apply(args=[eid]).get(timeout=30)
    classify_email.apply(args=[eid]).get(timeout=30)
    generate_explanation.apply(args=[eid]).get(timeout=30)
    print("  done")

print("All re-analysed")
