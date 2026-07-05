from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pymongo.errors import DuplicateKeyError

from app.agents.pipeline import AgentPipeline
from app.config import get_settings
from app.database import close_mongo_connection, connect_to_mongo, get_database
from app.schemas import IngestResponse, LogEntry


pipeline: AgentPipeline | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pipeline
    await connect_to_mongo()
    settings = get_settings()
    pipeline = AgentPipeline(get_database(), settings)
    yield
    await close_mongo_connection()


settings = get_settings()
app = FastAPI(title="AI-Agent SIEM MVP", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/ingest", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
async def ingest(log: LogEntry) -> IngestResponse:
    if pipeline is None:
        raise HTTPException(status_code=503, detail="Agent pipeline is not ready")

    db = get_database()
    document = log.dict()
    document["event_type"] = log.event_type.value
    document["severity"] = log.severity.value

    try:
        await db.logs.insert_one(document)
    except DuplicateKeyError as exc:
        raise HTTPException(status_code=409, detail=f"log_id already exists: {log.log_id}") from exc

    threat, alerts = await pipeline.process(log)
    return IngestResponse(
        stored=True,
        log_id=log.log_id,
        threat_detection=threat,
        alerts=[json_safe(alert) for alert in alerts],
    )


@app.get("/logs")
async def list_logs(limit: int = Query(default=100, ge=1, le=500)) -> list[dict[str, Any]]:
    db = get_database()
    cursor = db.logs.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)
    return [json_safe(item) async for item in cursor]


@app.get("/alerts")
async def list_alerts(limit: int = Query(default=50, ge=1, le=200)) -> list[dict[str, Any]]:
    db = get_database()
    cursor = db.alerts.find({}, {"_id": 0}).sort("updated_at", -1).limit(limit)
    return [json_safe(item) async for item in cursor]


@app.get("/stats/attack-types")
async def attack_type_stats() -> list[dict[str, Any]]:
    db = get_database()
    pipeline_query = [
        {"$group": {"_id": "$threat_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$project": {"_id": 0, "threat_type": "$_id", "count": 1}},
    ]
    return [item async for item in db.alerts.aggregate(pipeline_query)]


@app.get("/blocked-ips")
async def blocked_ips() -> list[dict[str, Any]]:
    db = get_database()
    cursor = db.blocked_ips.find({}, {"_id": 0}).sort("updated_at", -1)
    return [json_safe(item) async for item in cursor]


def json_safe(document: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in document.items():
        if isinstance(value, datetime):
            result[key] = value.isoformat()
        else:
            result[key] = value
    return result
