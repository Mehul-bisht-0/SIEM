import json
from typing import Any

import httpx


class NLPReportAgent:
    """Creates structured incident intelligence, using an LLM when configured."""

    def __init__(self, model_name: str, api_key: str | None, base_url: str, timeout_seconds: float):
        self.model_name = model_name
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    async def summarize(self, incident: dict[str, Any]) -> str:
        analysis = await self.analyze(incident)
        return analysis["summary"]

    async def analyze(self, incident: dict[str, Any]) -> dict[str, Any]:
        if self.api_key:
            try:
                return await self._analyze_with_llm(incident)
            except Exception as exc:  # noqa: BLE001 - demo fallback should never break ingestion.
                print(f"[NLPReportAgent] LLM fallback used: {exc}")
        return self._fallback_analysis(incident)

    async def _analyze_with_llm(self, incident: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "model": self.model_name,
            "temperature": 0.1,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a SOC analyst assistant for a demo SIEM. "
                        "Use only the incident data provided. "
                        "Return strict JSON with these keys: summary, risk_level, likely_attack, "
                        "mitre_tactic, recommended_actions, analyst_notes. "
                        "summary must be exactly 3 short sentences. "
                        "recommended_actions must be 3 to 6 concise defensive actions."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(self._incident_context(incident), default=str),
                },
            ],
        }

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            response.raise_for_status()

        content = response.json()["choices"][0]["message"]["content"]
        return self._normalize_analysis(json.loads(self._strip_json_fence(content)), provider="llm")

    def _fallback_analysis(self, incident: dict[str, Any]) -> dict[str, Any]:
        source_ip = incident.get("source_ip", "unknown source")
        threat_type = str(incident.get("threat_type", "suspicious activity"))
        stages = ", ".join(incident.get("attack_chain", [])) or "an anomalous event"
        confidence = float(incident.get("confidence_score", 0) or 0)

        analysis = {
            "summary": (
                f"{source_ip} triggered a {threat_type.replace('_', ' ')} alert with {confidence:.0%} confidence. "
                f"The correlated sequence includes {stages}. "
                "The response agent marked the source for blocking and queued the incident for analyst review."
            ),
            "risk_level": self._risk_level(incident),
            "likely_attack": self._likely_attack(threat_type),
            "mitre_tactic": self._mitre_tactic(threat_type),
            "recommended_actions": self._recommended_actions(threat_type),
            "analyst_notes": self._analyst_notes(threat_type),
        }
        return self._normalize_analysis(analysis, provider="fallback")

    @staticmethod
    def _incident_context(incident: dict[str, Any]) -> dict[str, Any]:
        return {
            "alert_id": incident.get("alert_id"),
            "threat_type": incident.get("threat_type"),
            "severity": incident.get("severity"),
            "confidence_score": incident.get("confidence_score"),
            "status": incident.get("status"),
            "source_ip": incident.get("source_ip"),
            "destination_ip": incident.get("destination_ip"),
            "attack_chain": incident.get("attack_chain", []),
            "related_log_ids": incident.get("related_log_ids", []),
        }

    def _normalize_analysis(self, analysis: dict[str, Any], provider: str) -> dict[str, Any]:
        summary = str(analysis.get("summary") or "").strip()
        likely_attack = str(analysis.get("likely_attack") or "Suspicious activity").strip()
        mitre_tactic = str(analysis.get("mitre_tactic") or "Unknown").strip()
        analyst_notes = str(analysis.get("analyst_notes") or "").strip()

        actions = analysis.get("recommended_actions") or []
        if isinstance(actions, str):
            actions = [actions]
        actions = [str(action).strip() for action in actions if str(action).strip()]

        risk_level = str(analysis.get("risk_level") or "medium").lower().strip()
        if risk_level not in {"low", "medium", "high", "critical"}:
            risk_level = "medium"

        return {
            "summary": summary,
            "risk_level": risk_level,
            "likely_attack": likely_attack,
            "mitre_tactic": mitre_tactic,
            "recommended_actions": actions[:6],
            "analyst_notes": analyst_notes,
            "llm_provider": provider,
        }

    @staticmethod
    def _strip_json_fence(content: str) -> str:
        stripped = content.strip()
        if stripped.startswith("```"):
            stripped = stripped.strip("`").strip()
            if stripped.lower().startswith("json"):
                stripped = stripped[4:]
        return stripped.strip()

    @staticmethod
    def _risk_level(incident: dict[str, Any]) -> str:
        severity = str(incident.get("severity", "")).lower()
        confidence = float(incident.get("confidence_score", 0) or 0)
        if severity == "critical" or confidence >= 0.94:
            return "critical"
        if severity == "high" or confidence >= 0.82:
            return "high"
        if severity == "medium" or confidence >= 0.6:
            return "medium"
        return "low"

    @staticmethod
    def _likely_attack(threat_type: str) -> str:
        mapping = {
            "credential_compromise_chain": "Credential compromise followed by privilege escalation",
            "brute_force_success": "Successful brute-force login",
            "brute_force": "Brute-force authentication attempt",
            "anomalous_port_scan": "Reconnaissance or exposed-service probing",
            "anomalous_malware": "Potential malware execution",
            "anomalous_data_exfiltration": "Potential data exfiltration",
            "anomalous_privilege_escalation": "Potential privilege escalation",
        }
        return mapping.get(threat_type, threat_type.replace("_", " ").title())

    @staticmethod
    def _mitre_tactic(threat_type: str) -> str:
        if "brute_force" in threat_type or "credential" in threat_type:
            return "Credential Access / Privilege Escalation"
        if "port_scan" in threat_type:
            return "Reconnaissance"
        if "malware" in threat_type:
            return "Execution"
        if "data_exfiltration" in threat_type:
            return "Exfiltration"
        if "privilege_escalation" in threat_type:
            return "Privilege Escalation"
        return "Defense Evasion"

    @staticmethod
    def _recommended_actions(threat_type: str) -> list[str]:
        if "credential" in threat_type or "brute_force" in threat_type:
            return [
                "Keep the source IP blocked and review whether it used rotating addresses.",
                "Force a password reset for the affected account and revoke active sessions.",
                "Verify MFA coverage and tighten login throttling or lockout policy.",
                "Review post-login activity for lateral movement or sensitive data access.",
            ]
        if "privilege_escalation" in threat_type:
            return [
                "Revoke the elevated session and disable the account pending review.",
                "Audit privilege changes, new admin memberships, and recent command history.",
                "Check the destination host for persistence mechanisms or suspicious binaries.",
            ]
        if "port_scan" in threat_type:
            return [
                "Block or rate-limit the scanning source at the perimeter.",
                "Validate exposed services against the approved asset inventory.",
                "Inspect firewall and IDS logs for follow-on exploitation attempts.",
            ]
        if "malware" in threat_type:
            return [
                "Isolate the affected host from the network.",
                "Run endpoint malware scanning and collect forensic artifacts.",
                "Rotate credentials used on the affected host.",
            ]
        if "data_exfiltration" in threat_type:
            return [
                "Temporarily restrict outbound traffic from the source host.",
                "Identify transferred files and destinations from proxy or flow logs.",
                "Rotate credentials and preserve evidence for incident response.",
            ]
        return [
            "Keep the mock block active while an analyst validates the alert.",
            "Pull surrounding logs for the source and destination IPs.",
            "Escalate if the same source appears in additional high-severity events.",
        ]

    @staticmethod
    def _analyst_notes(threat_type: str) -> str:
        if "credential" in threat_type or "brute_force" in threat_type:
            return "Confirm whether the successful login accessed sensitive systems after the failed-login burst."
        if "privilege_escalation" in threat_type:
            return "Prioritize account and host timeline review because privilege changes can enable persistence."
        if "data_exfiltration" in threat_type:
            return "Focus on outbound volume, destination reputation, and whether sensitive data paths were touched."
        return "Validate the source, destination, and adjacent events before promoting this demo alert to a real incident."
