import asyncio
import time

from scitoken_issuer.state import State


async def run():
    now = int(time.time())
    s = State()
    clients = await s.list_clients()
    for client in clients:
        if client['client_secret_expires_at'] < now:
            await s.delete_client(client['client_id'])


def main():
    asyncio.run(run())


if __name__ == '__main__':
    main()
