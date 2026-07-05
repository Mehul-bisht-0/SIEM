from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.schemas import LogEntry, Severity, ThreatResult


class CorrelationAgent:
    """Groups related events into attack chains and writes alert documents."""

    def __init__(self, database: AsyncIOMotorDatabase):
        self.db = database

    async def correlate(self, log: LogEntry, threat: ThreatResult) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        chain = await self._detect_attack_chain(log)
        if chain:
            alerts.append(await self._upsert_alert(log, chain, threat))

        if threat.is_anomaly and not chain:
            alerts.append(
                await self._upsert_alert(
                    log,
                    {
                        "threat_type": f"anomalous_{log.event_type.value}",
                        "severity": log.severity.value,
                        "confidence_score": threat.confidence_score,
                        "attack_chain": [log.event_type.value],
                        "related_log_ids": [log.log_id],
                    },
                    threat,
                )
            )
        return alerts

    async def _detect_attack_chain(self, log: LogEntry) -> dict[str, Any] | None:
        now = log.timestamp
        source_ip = log.source_ip

        failed_window_start = now - timedelta(seconds=30)
        failed_logs = await self._logs_for_source(
            source_ip,
            failed_window_start,
            now,
            event_type="failed_login",
        )

        chain_start = failed_logs[0]["timestamp"] if failed_logs else now - timedelta(minutes=5)
        chain_logs = await self._logs_for_source(source_ip, chain_start, now + timedelta(seconds=1))
        event_types = [item["event_type"] for item in sorted(chain_logs, key=lambda item: item["timestamp"])]
        related_log_ids = [item["log_id"] for item in chain_logs]

        if len(failed_logs) >= 10:
            has_success = "login_success" in event_types
            has_privilege = "privilege_escalation" in event_types
            if has_success and has_privilege:
                threat_type = "credential_compromise_chain"
                severity = Severity.critical.value
                confidence = 0.97
            elif has_success:
                threat_type = "brute_force_success"
                severity = Severity.high.value
                confidence = 0.91
            else:
                threat_type = "brute_force"
                severity = Severity.high.value
                confidence = 0.86

            condensed_chain = self._condense_chain(event_types)
            return {
                "threat_type": threat_type,
                "severity": severity,
                "confidence_score": confidence,
                "attack_chain": condensed_chain,
                "related_log_ids": related_log_ids,
            }

        if log.event_type.value == "privilege_escalation":
            lookback = await self._logs_for_source(source_ip, now - timedelta(minutes=5), now)
            lookback_types = [item["event_type"] for item in lookback]
            if "failed_login" in lookback_types and "login_success" in lookback_types:
                return {
                    "threat_type": "credential_compromise_chain",
                    "severity": Severity.critical.value,
                    "confidence_score": 0.94,
                    "attack_chain": self._condense_chain(lookback_types + [log.event_type.value]),
                    "related_log_ids": [item["log_id"] for item in lookback] + [log.log_id],
                }

        return None

    async def _logs_for_source(
        self,
        source_ip: str,
        start: datetime,
        end: datetime,
        event_type: str | None = None,
    ) -> list[dict[str, Any]]:
        query: dict[str, Any] = {
            "source_ip": source_ip,
            "timestamp": {"$gte": start, "$lte": end},
        }
        if event_type:
            query["event_type"] = event_type
        cursor = self.db.logs.find(query).sort("timestamp", 1)
        return await cursor.to_list(length=250)

    async def _upsert_alert(
        self,
        log: LogEntry,
        incident: dict[str, Any],
        threat: ThreatResult,
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        dedupe_start = now - timedelta(minutes=10)
        existing = await self.db.alerts.find_one(
            {
                "source_ip": log.source_ip,
                "threat_type": incident["threat_type"],
                "status": {"$ne": "resolved"},
                "created_at": {"$gte": dedupe_start},
            },
            sort=[("created_at", -1)],
        )

        confidence = max(float(incident["confidence_score"]), threat.confidence_score)
        update = {
            "$set": {
                "confidence_score": round(confidence, 3),
                "severity": incident["severity"],
                "destination_ip": log.destination_ip,
                "attack_chain": incident["attack_chain"],
                "updated_at": now,
            },
            "$addToSet": {"related_log_ids": {"$each": incident["related_log_ids"]}},
        }

        if existing:
            await self.db.alerts.update_one({"_id": existing["_id"]}, update)
            refreshed = await self.db.alerts.find_one({"_id": existing["_id"]})
            return self._clean(refreshed)

        alert = {
            "alert_id": f"alert-{uuid4().hex[:12]}",
            "threat_type": incident["threat_type"],
            "confidence_score": round(confidence, 3),
            "status": "open",
            "severity": incident["severity"],
            "source_ip": log.source_ip,
            "destination_ip": log.destination_ip,
            "attack_chain": incident["attack_chain"],
            "related_log_ids": incident["related_log_ids"],
            "summary": "",
            "risk_level": "medium",
            "likely_attack": "",
            "mitre_tactic": "",
            "recommended_actions": [],
            "analyst_notes": "",
            "llm_provider": "fallback",
            "created_at": now,
            "updated_at": now,
        }
        await self.db.alerts.insert_one(alert)
        return self._clean(alert)

    @staticmethod
    def _condense_chain(event_types: list[str]) -> list[str]:
        result: list[str] = []
        for event_type in event_types:
            if event_type not in result:
                result.append(event_type)
        return result

    @staticmethod
    def _clean(document: dict[str, Any] | None) -> dict[str, Any]:
        if not document:
            return {}
        document.pop("_id", None)
        return document
