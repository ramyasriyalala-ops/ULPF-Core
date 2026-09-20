import sys
import os

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from Validator import validate_event


def test_valid_event():

    event = {
        "event_id": "ULPF-001",
        "timestamp": "2026-09-18T12:10:22Z",
        "source_ip": "192.168.1.10",
        "destination_ip": "10.0.0.5",
        "action": "DENY",
        "raw_event": "Original firewall log"
    }

    result = validate_event(event)

    assert result["valid"] is True

    print("Valid event test: PASSED")


def test_invalid_ip():

    event = {
        "event_id": "ULPF-002",
        "timestamp": "2026-09-18T12:10:22Z",
        "source_ip": "invalid-ip",
        "raw_event": "Original firewall log"
    }

    result = validate_event(event)

    assert result["valid"] is False

    print("Invalid IP test: PASSED")


def test_missing_event_id():

    event = {
        "timestamp": "2026-09-18T12:10:22Z",
        "raw_event": "Original firewall log"
    }

    result = validate_event(event)

    assert result["valid"] is False

    print("Missing event ID test: PASSED")


if __name__ == "__main__":

    test_valid_event()
    test_invalid_ip()
    test_missing_event_id()

    print("\nAll validator tests passed!")