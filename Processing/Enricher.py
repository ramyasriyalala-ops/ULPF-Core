from datetime import datetime


def get_service_name(port):
    services = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MYSQL",
        3389: "RDP"
    }

    try:
        port = int(port)
        return services.get(port, "UNKNOWN")
    except (ValueError, TypeError):
        return "UNKNOWN"


def get_event_category(event):
    action = event.get("action", "UNKNOWN").upper()
    protocol = event.get("protocol", "UNKNOWN").upper()

    if action in ["DENY", "BLOCK", "DROP"]:
        return "SECURITY_DENIED"

    if protocol in ["HTTP", "HTTPS"]:
        return "WEB_TRAFFIC"

    if protocol == "DNS":
        return "DNS_TRAFFIC"

    if protocol in ["SSH", "TELNET", "RDP"]:
        return "REMOTE_ACCESS"

    return "NETWORK_EVENT"


def calculate_risk_level(event):
    action = event.get("action", "UNKNOWN").upper()
    protocol = event.get("protocol", "UNKNOWN").upper()

    if action in ["DENY", "BLOCK", "DROP"]:
        return "HIGH"

    if protocol in ["TELNET", "FTP"]:
        return "MEDIUM"

    return "LOW"


def enrich_event(event):
    enriched_event = event.copy()

    # Add service name using destination port
    if "destination_port" in enriched_event:
        enriched_event["service"] = get_service_name(
            enriched_event["destination_port"]
        )

    # Add event category
    enriched_event["event_category"] = get_event_category(
        enriched_event
    )

    # Add risk level
    enriched_event["risk_level"] = calculate_risk_level(
        enriched_event
    )

    # Add processing timestamp
    enriched_event["processed_at"] = datetime.utcnow().isoformat() + "Z"

    return enriched_event


if __name__ == "__main__":

    test_event = {
        "event_id": "ULPF-001",
        "timestamp": "2026-09-18T12:10:22Z",
        "source_ip": "192.168.1.10",
        "destination_ip": "10.0.0.5",
        "destination_port": 22,
        "action": "DENY",
        "protocol": "TCP",
        "raw_event": "Original firewall log"
    }

    result = enrich_event(test_event)

    print("Enriched Event:")
    print(result)