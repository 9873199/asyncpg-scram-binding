"""Acquire a real pool connection and verify the independent TLS/SCRAM peer.

The peer implements authentication and Terminate only. Terminating the pool
avoids treating its lack of SQL/reset support as a product defect.
"""
import asyncio
import importlib.util
from pathlib import Path
import sys

import asyncpg
import pytest

spec = importlib.util.spec_from_file_location(
    'pool_wire_peer', Path(__file__).with_name('pg-wire-peer.py'))
wire = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = wire
spec.loader.exec_module(wire)


@pytest.mark.parametrize('dsn', [False, True])
def test_pool_acquire_uses_bound_authentication(dsn):
    async def scenario():
        async with wire.Peer().serve() as peer:
            kwargs = dict(ssl=peer.client_context, timeout=4,
                          min_size=1, max_size=1)
            if dsn:
                kwargs['dsn'] = (
                    'postgresql://local-test-user:local-test-password'
                    '@127.0.0.1:' + str(peer.port)
                    + '/test?channel_binding=require')
            else:
                kwargs.update(host='127.0.0.1', port=peer.port,
                              user='local-test-user',
                              password=peer.password.decode(),
                              database='test', channel_binding='require')
            pool = await asyncpg.create_pool(**kwargs)
            try:
                connection = await pool.acquire(timeout=4)
                assert not connection.is_closed()
                await asyncio.sleep(.03)
                assert not peer.errors, peer.errors
                assert len(peer.sessions) == 1
                session = peer.sessions[0]
                assert session['authenticated']
                assert session['mechanism'] == b'SCRAM-SHA-256-PLUS'
                assert session['binding_hex'] == (
                    b'p=tls-server-end-point,,' + peer.binding).hex()
            finally:
                pool.terminate()
    asyncio.run(scenario())
