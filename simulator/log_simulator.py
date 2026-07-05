from __future__ import annotations

import argparse
import random
import time
from datetime import datetime, timezone
from uuid import uuid4

import requests


BENIGN_EVENTS = [
    ("normal", "low"),
    ("config_change", "medium"),
    ("login_success", "low"),
    ("failed_login", "medium"),
    ("port_scan", "medium"),
]

DESTINATIONS = ["10.0.2.10", "10.0.2.11", "10.0.2.12", "172.16.4.20"]
NORMAL_SOURCES = ["10.0.1.23", "10.0.1.24", "192.168.1.44", "172.16.1.50"]
ATTACK_SOURCE = "203.0.113.44"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_log(source_ip: str, destination_ip: str, event_type: str, severity: str, message: str = "") -> dict:
    return {
        "log_id": f"log-{uuid4().hex[:12]}",
        "timestamp": now_iso(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "event_type": event_type,
        "severity": severity,
        "message": message,
        "metadata": {"simulated": True},
    }


def post_log(api_url: str, payload: dict) -> None:
    try:
        response = requests.post(api_url, json=payload, timeout=5)
        response.raise_for_status()
        result = response.json()
        anomaly = result["threat_detection"]["is_anomaly"]
        alert_count = len(result.get("alerts", []))
        print(
            f"posted {payload['event_type']:<22} {payload['source_ip']:<15} "
            f"anomaly={str(anomaly):<5} alerts={alert_count}"
        )
    except requests.RequestException as exc:
        print(f"post failed: {exc}")


def benign_log() -> dict:
    event_type, severity = random.choice(BENIGN_EVENTS)
    return make_log(
        random.choice(NORMAL_SOURCES),
        random.choice(DESTINATIONS),
        event_type,
        severity,
        f"Simulated {event_type}",
    )


def send_brute_force_chain(api_url: str, delay: float) -> None:
    destination = random.choice(DESTINATIONS)
    print("\n--- injecting brute-force attack chain ---")
    for index in range(10):
        post_log(
            api_url,
            make_log(
                ATTACK_SOURCE,
                destination,
                "failed_login",
                "high",
                f"Failed login attempt {index + 1}/10 from suspicious source",
            ),
        )
        time.sleep(delay)

    post_log(
        api_url,
        make_log(
            ATTACK_SOURCE,
            destination,
            "login_success",
            "high",
            "Successful login after repeated failures",
        ),
    )
    time.sleep(delay)

    post_log(
        api_url,
        make_log(
            ATTACK_SOURCE,
            destination,
            "privilege_escalation",
            "critical",
            "User obtained elevated privileges after suspicious login",
        ),
    )
    print("--- brute-force chain complete ---\n")


def run(api_url: str, once: bool, min_delay: float, max_delay: float) -> None:
    if once:
        send_brute_force_chain(api_url, min_delay)
        return

    counter = 0
    while True:
        counter += 1
        if counter % 16 == 0:
            send_brute_force_chain(api_url, min_delay)
        else:
            post_log(api_url, benign_log())
        time.sleep(random.uniform(min_delay, max_delay))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simulate SIEM logs and attack chains.")
    parser.add_argument("--api-url", default="http://localhost:8000/ingest", help="Backend ingest endpoint")
    parser.add_argument("--once", action="store_true", help="Send one brute-force chain and exit")
    parser.add_argument("--min-delay", type=float, default=0.7, help="Minimum delay between events")
    parser.add_argument("--max-delay", type=float, default=2.2, help="Maximum delay between normal events")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run(args.api_url, args.once, args.min_delay, args.max_delay)
