from datetime import datetime, timezone
from typing import Any

import httpx
from motor.motor_asyncio import AsyncIOMotorDatabase


class ResponseAgent:
    """Mocks defensive response by recording blocked IPs and printing an alert."""

    def __init__(self, database: AsyncIOMotorDatabase, webhook_url: str | None = None):
        self.db = database
        self.webhook_url = webhook_url

    async def respond(self, alert: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        source_ip = alert["source_ip"]
        await self.db.blocked_ips.update_one(
            {"source_ip": source_ip},
            {
                "$set": {
                    "source_ip": source_ip,
                    "reason": alert["threat_type"],
                    "alert_id": alert["alert_id"],
                    "updated_at": now,
                },
                "$setOnInsert": {"created_at": now},
            },
            upsert=True,
        )
        await self.db.alerts.update_one(
            {"alert_id": alert["alert_id"]},
            {"$set": {"status": "blocked", "updated_at": now}},
        )
        alert["status"] = "blocked"
        alert["updated_at"] = now

        print(f"[ResponseAgent] Mock block applied to {source_ip} for {alert['threat_type']}")
        if self.webhook_url:
            await self._send_webhook(alert)
        return alert

    async def _send_webhook(self, alert: dict[str, Any]) -> None:
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                await client.post(self.webhook_url, json=self._json_safe(alert))
        except Exception as exc:  # noqa: BLE001 - webhook is optional in the MVP.
            print(f"[ResponseAgent] Mock webhook failed: {exc}")

    @staticmethod
    def _json_safe(payload: dict[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in payload.items():
            if isinstance(value, datetime):
                result[key] = value.isoformat()
            else:
                result[key] = value
        return result
