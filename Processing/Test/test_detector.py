import json
import sys
import os

processing_folder = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

sys.path.insert(0, processing_folder)

from Detector  import analyze_event


# Load sample events
with open("Sample_events.json", "r") as file:
    events = json.load(file)


print("========== THREAT DETECTION TEST ==========")

for event in events:

    result = analyze_event(event)

    print("\nEvent ID:", event["event_id"])
    print("Detection Status:", result["detection_status"])

    if result["threats"]:
        print("Threats detected:")

        for threat in result["threats"]:
            print(
                "-",
                threat["type"],
                "| Severity:",
                threat["severity"]
            )
    else:
        print("No threats detected.")