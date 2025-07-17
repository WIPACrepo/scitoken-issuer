import asyncio

from .config import config_logging
from .server import Server


config_logging()


# start server
async def main():
    s = Server()
    await s.start()
    try:
        await asyncio.Event().wait()
    finally:
        await s.stop()

asyncio.run(main())
