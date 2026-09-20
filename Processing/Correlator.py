from collections import defaultdict


def correlate_events(events):
    """
    Analyze multiple events and identify related activity.
    """

    results = []

    # Group events by source IP
    events_by_ip = defaultdict(list)

    for event in events:
        source_ip = event.get("source_ip", "UNKNOWN")
        events_by_ip[source_ip].append(event)

    # Analyze each source IP
    for source_ip, ip_events in events_by_ip.items():

        denied_count = 0
        failed_count = 0
        successful_count = 0

        ports = set()

        for event in ip_events:

            action = event.get("action", "UNKNOWN").upper()

            if action in ["DENY", "BLOCK", "DROP"]:
                denied_count += 1

            if action in ["FAIL", "FAILED", "FAILURE"]:
                failed_count += 1

            if action in ["SUCCESS", "ALLOW", "ACCEPT"]:
                successful_count += 1

            if event.get("destination_port"):
                ports.add(event.get("destination_port"))

        # Rule 1: Multiple denied connections
        if denied_count >= 3:
            results.append({
                "source_ip": source_ip,
                "pattern": "REPEATED_DENIED_CONNECTIONS",
                "severity": "HIGH",
                "event_count": denied_count,
                "description": "Multiple denied connections detected from the same source IP"
            })

        # Rule 2: Multiple failed attempts
        if failed_count >= 3:
            results.append({
                "source_ip": source_ip,
                "pattern": "MULTIPLE_FAILED_ATTEMPTS",
                "severity": "HIGH",
                "event_count": failed_count,
                "description": "Multiple failed attempts detected from the same source IP"
            })

        # Rule 3: Many different destination ports
        if len(ports) >= 5:
            results.append({
                "source_ip": source_ip,
                "pattern": "POSSIBLE_PORT_SCAN",
                "severity": "HIGH",
                "event_count": len(ports),
                "description": "Multiple destination ports contacted by the same source IP"
            })

        # Rule 4: Failed attempts followed by success
        if failed_count >= 2 and successful_count >= 1:
            results.append({
                "source_ip": source_ip,
                "pattern": "FAILED_THEN_SUCCESS",
                "severity": "HIGH",
                "event_count": len(ip_events),
                "description": "Failed attempts followed by a successful connection"
            })

    return results


if __name__ == "__main__":

    test_events = [

        {
            "event_id": "ULPF-001",
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.5",
            "destination_port": 22,
            "action": "DENY",
            "protocol": "TCP"
        },

        {
            "event_id": "ULPF-002",
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.5",
            "destination_port": 22,
            "action": "DENY",
            "protocol": "TCP"
        },

        {
            "event_id": "ULPF-003",
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.5",
            "destination_port": 22,
            "action": "DENY",
            "protocol": "TCP"
        },

        {
            "event_id": "ULPF-004",
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.5",
            "destination_port": 22,
            "action": "SUCCESS",
            "protocol": "TCP"
        }
    ]

    results = correlate_events(test_events)

    print("Correlation Results:")

    for result in results:
        print(result)