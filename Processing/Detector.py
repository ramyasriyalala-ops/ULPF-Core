def detect_threats(event):
    threats = []

    action = event.get("action", "UNKNOWN").upper()
    protocol = event.get("protocol", "UNKNOWN").upper()
    source_ip = event.get("source_ip", "")
    destination_port = event.get("destination_port", None)

    # Rule 1: Denied or blocked connection
    if action in ["DENY", "BLOCK", "DROP"]:
        threats.append({
            "type": "DENIED_CONNECTION",
            "severity": "MEDIUM",
            "description": "Connection was denied or blocked"
        })

    # Rule 2: Telnet usage
    if protocol == "TELNET":
        threats.append({
            "type": "INSECURE_PROTOCOL",
            "severity": "HIGH",
            "description": "Telnet connection detected"
        })

    # Rule 3: Suspicious remote access port
    if destination_port in [23, 3389]:
        threats.append({
            "type": "SUSPICIOUS_REMOTE_ACCESS",
            "severity": "HIGH",
            "description": "Remote access service detected"
        })

    # Rule 4: SSH connection
    if destination_port == 22:
        threats.append({
            "type": "SSH_ACTIVITY",
            "severity": "LOW",
            "description": "SSH activity detected"
        })

    # Rule 5: Missing source IP
    if not source_ip:
        threats.append({
            "type": "MISSING_SOURCE",
            "severity": "LOW",
            "description": "Source IP address is missing"
        })

    # Final detection status
    if threats:
        detection_status = "THREAT_DETECTED"
    else:
        detection_status = "NO_THREAT"

    return {
        "detection_status": detection_status,
        "threats": threats
    }


def analyze_event(event):
    detection_result = detect_threats(event)

    analyzed_event = event.copy()

    analyzed_event["detection_status"] = (
        detection_result["detection_status"]
    )

    analyzed_event["threats"] = detection_result["threats"]

    return analyzed_event


if __name__ == "__main__":

    test_event = {
        "event_id": "ULPF-001",
        "timestamp": "2026-09-18T12:10:22Z",
        "source_ip": "192.168.1.10",
        "destination_ip": "10.0.0.5",
        "destination_port": 23,
        "action": "DENY",
        "protocol": "TELNET",
        "raw_event": "Original firewall log"
    }

    result = analyze_event(test_event)

    print("Threat Detection Result:")
    print(result)