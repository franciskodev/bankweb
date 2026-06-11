import asyncio

import asyncpg

from .config import DB_CONFIG


async def db_connect():
    return await asyncpg.connect(**DB_CONFIG)


def db_run(coro):
    return asyncio.run(coro)
