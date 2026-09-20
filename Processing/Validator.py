import ipaddress
from datetime import datetime


def validate_ip(ip):
    """Validate an IPv4 or IPv6 address."""
    if not ip:
        return False

    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_timestamp(timestamp):
    """Validate ISO-format timestamp."""
    if not timestamp:
        return False

    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def validate_event(event):
    """
    Validate a normalized ULPF event.

    Returns:
        {
            "valid": True/False,
            "errors": [...]
        }
    """

    errors = []

    # Required fields
    required_fields = [
        "event_id",
        "timestamp",
        "raw_event"
    ]

    for field in required_fields:
        if field not in event or event[field] in [None, ""]:
            errors.append(f"Missing required field: {field}")

    # Validate timestamp
    if "timestamp" in event and event["timestamp"]:
        if not validate_timestamp(event["timestamp"]):
            errors.append("Invalid timestamp")

    # Validate source IP
    if "source_ip" in event and event["source_ip"]:
        if not validate_ip(event["source_ip"]):
            errors.append("Invalid source IP")

    # Validate destination IP
    if "destination_ip" in event and event["destination_ip"]:
        if not validate_ip(event["destination_ip"]):
            errors.append("Invalid destination IP")

    # Validate action
    valid_actions = [
        "ALLOW",
        "DENY",
        "BLOCK",
        "DROP",
        "ACCEPT",
        "FAIL",
        "SUCCESS",
        "UNKNOWN"
    ]

    if "action" in event and event["action"]:
        if event["action"].upper() not in valid_actions:
            errors.append(
                f"Invalid action: {event['action']}"
            )

    if len(errors) == 0:
        return {
            "valid": True,
            "errors": []
        }

    return {
        "valid": False,
        "errors": errors
    }


if __name__ == "__main__":

    test_event = {
        "event_id": "ULPF-001",
        "timestamp": "2026-09-18T12:10:22Z",
        "source_ip": "192.168.1.10",
        "destination_ip": "10.0.0.5",
        "action": "DENY",
        "raw_event": "<original firewall log>"
    }

    result = validate_event(test_event)

    print("Validation Result:")
    print(result)