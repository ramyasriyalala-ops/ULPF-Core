import json
import sys
import os

processing_folder = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, processing_folder)

from Pipeline import process_events

with open("Test/sample_events.json", "r") as file:
    events = json.load(file)

result = process_events(events)

output_file = "Test/processed_output.json"

with open(output_file, "w") as file:
    json.dump(result, file, indent=4)

print("========== ULPF PIPELINE ==========")
print("Processing completed successfully.")
print("Processed events:", len(result["processed_events"]))
print("Correlation results:", len(result["correlation_results"]))
print("Output saved to:", output_file)