import asyncio
import os
import sys

# Ensure backend can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app.db.mongodb import mongo_manager
from backend.app.db.neo4j import neo4j_manager
from backend.app.db.seed_data import seed_all

async def main():
    print("=" * 60)
    print("SentinelGraph-AI Database Seeder")
    print("=" * 60)
    await mongo_manager.connect()
    await neo4j_manager.connect()
    await seed_all(force=True)
    print("Seeding completed successfully!")
    await mongo_manager.close()
    await neo4j_manager.close()

if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
