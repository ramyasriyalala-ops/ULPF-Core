def normalize_action(action):
    if not action:
        return "UNKNOWN"

    action = action.strip().upper()

    action_map = {
        "ALLOW": "ALLOW",
        "ACCEPT": "ALLOW",
        "PERMIT": "ALLOW",

        "DENY": "DENY",
        "DENIED": "DENY",
        "DROP": "DENY",
        "BLOCK": "DENY",
        "BLOCKED": "DENY",

        "SUCCESS": "SUCCESS",
        "SUCCEEDED": "SUCCESS",

        "FAIL": "FAIL",
        "FAILED": "FAIL",
        "FAILURE": "FAIL"
    }

    return action_map.get(action, "UNKNOWN")


def normalize_protocol(protocol):
    if not protocol:
        return "UNKNOWN"

    protocol = protocol.strip().upper()

    protocol_map = {
        "TCP": "TCP",
        "UDP": "UDP",
        "ICMP": "ICMP",
        "HTTP": "HTTP",
        "HTTPS": "HTTPS",
        "SSH": "SSH",
        "FTP": "FTP",
        "DNS": "DNS"
    }

    return protocol_map.get(protocol, protocol)


def normalize_event(event):
    normalized_event = event.copy()

    # Normalize action
    if "action" in normalized_event:
        normalized_event["action"] = normalize_action(
            normalized_event["action"]
        )

    # Normalize protocol
    if "protocol" in normalized_event:
        normalized_event["protocol"] = normalize_protocol(
            normalized_event["protocol"]
        )

    # Make sure raw event is preserved
    if "raw_event" not in normalized_event:
        normalized_event["raw_event"] = ""

    return normalized_event


if __name__ == "__main__":

    test_event = {
        "event_id": "ULPF-001",
        "timestamp": "2026-09-18T12:10:22Z",
        "source_ip": "192.168.1.10",
        "destination_ip": "10.0.0.5",
        "action": "drop",
        "protocol": "tcp",
        "raw_event": "Original firewall log"
    }

    result = normalize_event(test_event)

    print("Original Event:")
    print(test_event)

    print("\nNormalized Event:")
    print(result)