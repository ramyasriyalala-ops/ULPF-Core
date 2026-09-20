from Normalizer import normalize_event
from Validator import validate_event
from Enricher import enrich_event
from Detector import analyze_event
from Correlator import correlate_events


def process_event(event):
    """
    Process one event through the complete ULPF pipeline.
    """

    # Step 1: Normalize
    normalized_event = normalize_event(event)

    # Step 2: Validate
    validation_result = validate_event(normalized_event)

    if not validation_result["valid"]:
        return {
            "status": "INVALID",
            "validation_errors": validation_result["errors"],
            "event": normalized_event
        }

    # Step 3: Enrich
    enriched_event = enrich_event(normalized_event)

    # Step 4: Detect threats
    analyzed_event = analyze_event(enriched_event)

    return {
        "status": "PROCESSED",
        "event": analyzed_event
    }


def process_events(events):
    """
    Process multiple events and perform correlation.
    """

    processed_events = []

    # Process each event
    for event in events:
        result = process_event(event)
        processed_events.append(result)

    # Select successfully processed events
    valid_events = []

    for result in processed_events:
        if result["status"] == "PROCESSED":
            valid_events.append(result["event"])

    # Correlate multiple events
    correlation_results = correlate_events(valid_events)

    return {
        "processed_events": processed_events,
        "correlation_results": correlation_results
    }


if __name__ == "__main__":

    test_events = [

        {
            "event_id": "ULPF-001",
            "timestamp": "2026-09-18T12:10:22Z",
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.5",
            "destination_port": 22,
            "action": "DENY",
            "protocol": "TCP",
            "raw_event": "Original firewall log 1"
        },

        {
            "event_id": "ULPF-002",
            "timestamp": "2026-09-18T12:11:22Z",
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.5",
            "destination_port": 22,
            "action": "DENY",
            "protocol": "TCP",
            "raw_event": "Original firewall log 2"
        },

        {
            "event_id": "ULPF-003",
            "timestamp": "2026-09-18T12:12:22Z",
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.5",
            "destination_port": 22,
            "action": "DENY",
            "protocol": "TCP",
            "raw_event": "Original firewall log 3"
        },

        {
            "event_id": "ULPF-004",
            "timestamp": "2026-09-18T12:13:22Z",
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.5",
            "destination_port": 22,
            "action": "SUCCESS",
            "protocol": "TCP",
            "raw_event": "Original firewall log 4"
        }
    ]

    result = process_events(test_events)

    print("\n========== ULPF PROCESSING RESULT ==========")

    print("\n--- Processed Events ---")

    for event in result["processed_events"]:
        print(event)

    print("\n--- Correlation Results ---")

    for correlation in result["correlation_results"]:
        print(correlation)