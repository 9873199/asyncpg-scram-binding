"""require must reject trust, cleartext and MD5 authentication, including TLS."""
import asyncio
import importlib.util
from pathlib import Path
import sys

import asyncpg
import pytest

spec = importlib.util.spec_from_file_location('pg_nonsasl_peer', Path(__file__).with_name('pg-nonsasl-peer.py'))
peer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = peer
spec.loader.exec_module(peer)


@pytest.mark.parametrize('tls', [False, True])
@pytest.mark.parametrize('auth_code', [0, 3, 5])
def test_require_refuses_non_channel_bound_auth_before_password(tls, auth_code):
    async def scenario():
        async with peer.NonSASLPeer(tls=tls, auth_code=auth_code).serve() as p:
            with pytest.raises((asyncpg.InterfaceError, asyncpg.PostgresError, ValueError)):
                await asyncpg.connect(host='127.0.0.1', port=p.port, user='local-test-user',
                    password=p.password.decode(), database='test', ssl=p.client_context if tls else False,
                    channel_binding='require', timeout=4)
            await asyncio.sleep(.03)
            assert not p.errors
            assert all(not s['password_sent'] for s in p.sessions), 'require leaked password/proof to a non-SASL authentication challenge'
    asyncio.run(scenario())
