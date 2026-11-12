"""Local PostgreSQL authentication example using the frozen asyncpg package."""
import asyncio
import importlib.util
from pathlib import Path
import sys

import asyncpg

spec = importlib.util.spec_from_file_location('local_postgresql', Path(__file__).with_name('pg-wire-peer.py'))
wire = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = wire
spec.loader.exec_module(wire)


async def example(mode, *, bad_signature=False):
    async with wire.Peer(bad_server_signature=bad_signature).serve() as server:
        print('TLS connection, channel_binding=' + mode, flush=True)
        try:
            connection = await asyncpg.connect(host='127.0.0.1', port=server.port,
                user='local-test-user', password=server.password.decode(), database='test',
                ssl=server.client_context, channel_binding=mode, timeout=4)
        except Exception as error:
            print('Connection ended:', type(error).__name__, str(error), flush=True)
        else:
            await connection.close()
            await asyncio.sleep(.03)
            print('Connected with:', server.sessions[-1].get('mechanism', b'unknown').decode(), flush=True)
        print('', flush=True)


async def main():
    print('Local PostgreSQL authentication\n', flush=True)
    for mode in ('disable', 'prefer', 'require'):
        await example(mode)
    print('Server signature check', flush=True)
    await example('require', bad_signature=True)


asyncio.run(main())
