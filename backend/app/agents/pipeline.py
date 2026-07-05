from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.agents.correlation import CorrelationAgent
from app.agents.nlp_report import NLPReportAgent
from app.agents.response import ResponseAgent
from app.agents.threat_detection import ThreatDetectionAgent
from app.config import Settings
from app.schemas import LogEntry, ThreatResult


class AgentPipeline:
    """Coordinates threat detection, correlation, reporting, and response agents."""

    def __init__(self, database: AsyncIOMotorDatabase, settings: Settings):
        self.db = database
        self.threat_detection = ThreatDetectionAgent(settings.model_path)
        self.correlation = CorrelationAgent(database)
        self.reporter = NLPReportAgent(
            settings.openai_model,
            settings.openai_api_key,
            settings.openai_base_url,
            settings.llm_timeout_seconds,
        )
        self.response = ResponseAgent(database, settings.mock_webhook_url)

    async def process(self, log: LogEntry) -> tuple[ThreatResult, list[dict[str, Any]]]:
        threat = self.threat_detection.analyze(log)
        alerts = await self.correlation.correlate(log, threat)
        processed: list[dict[str, Any]] = []

        for alert in alerts:
            if not alert:
                continue
            llm_analysis = await self.reporter.analyze(alert)
            await self.db.alerts.update_one(
                {"alert_id": alert["alert_id"]},
                {"$set": {**llm_analysis, "updated_at": datetime.now(timezone.utc)}},
            )
            alert.update(llm_analysis)

            should_block = alert["severity"] in {"high", "critical"} or alert["confidence_score"] >= 0.82
            if should_block:
                alert = await self.response.respond(alert)
            processed.append(alert)

        return threat, processed
