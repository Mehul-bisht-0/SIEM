from datetime import datetime
from ipaddress import ip_address

from app.schemas import LogEntry

EVENT_WEIGHTS = {
    "normal": 0,
    "config_change": 1,
    "failed_login": 3,
    "login_success": 2,
    "port_scan": 5,
    "privilege_escalation": 7,
    "malware": 9,
    "data_exfiltration": 10,
}

SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 3,
    "high": 6,
    "critical": 9,
}


def private_ip_flag(value: str) -> int:
    try:
        return int(ip_address(value).is_private)
    except ValueError:
        return 0


def ip_octet_sum(value: str) -> int:
    try:
        return sum(int(part) for part in value.split(".")[:4])
    except ValueError:
        return 0


def hour_of_day(value: datetime) -> int:
    return value.hour


def vectorize_log(log: LogEntry) -> list[float]:
    event_weight = EVENT_WEIGHTS.get(log.event_type.value, 0)
    severity_weight = SEVERITY_WEIGHTS.get(log.severity.value, 1)

    return [
        float(event_weight),
        float(severity_weight),
        float(hour_of_day(log.timestamp)),
        float(private_ip_flag(log.source_ip)),
        float(private_ip_flag(log.destination_ip)),
        float(ip_octet_sum(log.source_ip)),
        float(ip_octet_sum(log.destination_ip)),
        float(event_weight * severity_weight),
    ]
