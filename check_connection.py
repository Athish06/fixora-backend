import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def check():
    client = AsyncIOMotorClient('mongodb+srv://Athish:Athish2006@cluster0.qi8bb8b.mongodb.net/')
    db = client['IP']
    result = await db.github_connections.find_one()
    print('Connection data:')
    if result:
        print(f'  user_id: {result.get("user_id")}')
        print(f'  github_username: {result.get("github_username")}')
        print(f'  installation_id: {result.get("installation_id")}')
        print(f'  has_access_token: {bool(result.get("access_token"))}')
    else:
        print('  No connection found')
    client.close()

asyncio.run(check())
