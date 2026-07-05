# AI-Agent Based SIEM Analytics System MVP

This workspace contains a functional demo SIEM pipeline:

`Log Ingestion -> Threat Detection Agent -> Correlation Agent -> LLM Incident Analysis -> Response Agent -> Dashboard`

It is intentionally small and demo-oriented. MongoDB stores logs, alerts, and mock blocked IPs; FastAPI runs the agent pipeline; React displays the live dashboard; and `log_simulator.py` injects a brute-force pattern end to end.

## Stack

- Backend: FastAPI, Motor, MongoDB, Scikit-learn, OpenAI-compatible LLM calls
- ML: Isolation Forest saved as `models/isolation_forest.pkl`
- Frontend: React, Vite, Recharts, Lucide icons
- Demo runtime: Docker Compose

## Run With Docker

```bash
docker compose up --build
```

Open:

- Dashboard: http://localhost:5173
- API docs: http://localhost:8000/docs
- Health: http://localhost:8000/health

In another terminal, inject one brute-force attack chain:

```bash
docker compose run --rm simulator python log_simulator.py --api-url http://backend:8000/ingest --once --min-delay 0.5
```

Or run continuous simulated traffic:

```bash
docker compose --profile demo up simulator
```

## Local Development

Backend:

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m app.ml.train_model
uvicorn app.main:app --reload
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Simulator:

```bash
cd simulator
pip install -r requirements.txt
python log_simulator.py --once
```

## API

### `POST /ingest`

Accepts raw JSON logs:

```json
{
  "log_id": "log-demo-001",
  "timestamp": "2026-05-27T10:00:00Z",
  "source_ip": "203.0.113.44",
  "destination_ip": "10.0.2.10",
  "event_type": "failed_login",
  "severity": "high"
}
```

The endpoint stores the log, runs anomaly detection, correlates attack chains, generates a 3-sentence summary, and applies a mock block for high-confidence alerts.

Alerts also store LLM incident intelligence:

```json
{
  "summary": "Three-sentence analyst summary",
  "risk_level": "critical",
  "likely_attack": "Credential compromise followed by privilege escalation",
  "mitre_tactic": "Credential Access / Privilege Escalation",
  "recommended_actions": [
    "Keep the source IP blocked and review whether it used rotating addresses.",
    "Force a password reset for the affected account and revoke active sessions."
  ],
  "analyst_notes": "Confirm whether the successful login accessed sensitive systems."
}
```

### Dashboard Endpoints

- `GET /logs`
- `GET /alerts`
- `GET /stats/attack-types`
- `GET /blocked-ips`

## Model Training

The backend loads `models/isolation_forest.pkl`. If it is missing, startup trains a fallback Isolation Forest model from synthetic SIEM-like records so the demo always works.

To train from an NSL-KDD preprocessed CSV, provide `NSL_KDD_CSV`:

```bash
cd backend
$env:NSL_KDD_CSV="C:\path\to\nsl-kdd-preprocessed.csv"
python -m app.ml.train_model
```

## Agent Behavior

- Threat Detection Agent: vectorizes each log and scores it with Isolation Forest plus a small high-risk event heuristic.
- Correlation Agent: groups repeated failed logins, successful login, and privilege escalation into a correlated alert.
- LLM Incident Analysis Agent: calls an OpenAI-compatible chat endpoint to produce summary, likely attack, MITRE-style tactic, risk level, analyst notes, and recommended countermeasures.
- Response Agent: writes the source IP into `blocked_ips` and prints a mock block action.
- NLP fallback: if no API key is configured or the LLM call fails, the backend still returns deterministic incident intelligence for the demo.

## LLM Configuration

Copy `.env.example` to `.env` or set environment variables before starting Docker:

```bash
OPENAI_API_KEY=your_api_key
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-4o-mini
LLM_TIMEOUT_SECONDS=20
```

For OpenAI-compatible providers, set `OPENAI_BASE_URL` and `OPENAI_MODEL` to that provider's values. The app posts to `{OPENAI_BASE_URL}/chat/completions` and expects the model to return JSON.
