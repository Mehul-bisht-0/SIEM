from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.config import get_settings

client: AsyncIOMotorClient | None = None
db: AsyncIOMotorDatabase | None = None


async def connect_to_mongo() -> None:
    global client, db
    settings = get_settings()
    client = AsyncIOMotorClient(settings.mongodb_uri)
    db = client[settings.mongodb_db]
    await create_indexes(db)


async def close_mongo_connection() -> None:
    if client is not None:
        client.close()


def get_database() -> AsyncIOMotorDatabase:
    if db is None:
        raise RuntimeError("MongoDB is not initialized")
    return db


async def create_indexes(database: AsyncIOMotorDatabase) -> None:
    await database.logs.create_index("log_id", unique=True)
    await database.logs.create_index([("source_ip", 1), ("timestamp", -1)])
    await database.logs.create_index("timestamp")
    await database.alerts.create_index("alert_id", unique=True)
    await database.alerts.create_index([("source_ip", 1), ("status", 1), ("created_at", -1)])
    await database.blocked_ips.create_index("source_ip", unique=True)
