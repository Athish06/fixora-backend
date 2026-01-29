# Database connection configuration
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from config.settings import get_settings
import logging

logger = logging.getLogger(__name__)
settings = get_settings()

class Database:
    client: AsyncIOMotorClient = None
    db: AsyncIOMotorDatabase = None

    @classmethod
    async def connect_db(cls):
        try:
            cls.client = AsyncIOMotorClient(settings.mongo_url)
            cls.db = cls.client[settings.db_name]
            
            # Create indexes for users collection
            await cls.db.users.create_index('email', unique=True)
            await cls.db.users.create_index('id', unique=True)
            
            logger.info(f'Connected to MongoDB: {settings.db_name}')
        except Exception as e:
            logger.error(f'Failed to connect to MongoDB: {e}')
            raise

    @classmethod
    async def close_db(cls):
        if cls.client:
            cls.client.close()
            logger.info('Closed MongoDB connection')

    @classmethod
    def get_db(cls) -> AsyncIOMotorDatabase:
        return cls.db

async def get_database() -> AsyncIOMotorDatabase:
    return Database.get_db()
