"""Independent RFC5929 certificate selection, deterministic nonce, and mismatch checks."""
import asyncio
import base64
import importlib.util
from pathlib import Path
import secrets
import sys
from unittest.mock import patch

import asyncpg
import pytest

spec = importlib.util.spec_from_file_location('scram_certificate_peer', Path(__file__).with_name('certificate-peer.py'))
peer_module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = peer_module
spec.loader.exec_module(peer_module)
CertificatePeer = peer_module.CertificatePeer


async def connect(peer):
    return await asyncpg.connect(host='127.0.0.1', port=peer.port,
        user='local-test-user', password=peer.password.decode(), database='test',
        ssl=peer.client_context, channel_binding='require', timeout=4)


@pytest.mark.parametrize('algorithm', ['sha256', 'sha384', 'sha512', 'sha1', 'md5'])
def test_real_certificate_digest_and_deterministic_nonce(algorithm):
    async def scenario():
        async with CertificatePeer(algorithm).serve() as peer:
            with patch.object(secrets, 'token_bytes', side_effect=lambda size: b'\x1a' * size):
                connection = await connect(peer)
                await connection.close()
            await asyncio.sleep(.03)
            assert not peer.errors, peer.errors
            session = peer.sessions[0]
            assert session['authenticated']
            assert session['mechanism'] == b'SCRAM-SHA-256-PLUS'
            nonce = session['first'].split(',r=', 1)[1].encode()
            raw = base64.b64decode(nonce)
            assert raw and raw == b'\x1a' * len(raw)
            expected = b'p=tls-server-end-point,,' + peer.binding
            assert bytes.fromhex(session['binding_hex']) == expected
    asyncio.run(scenario())


def test_changed_certificate_binding_does_not_authenticate():
    async def scenario():
        async with CertificatePeer(mismatch=True).serve() as peer:
            with pytest.raises((asyncpg.InterfaceError, asyncpg.PostgresError, ConnectionError)):
                await connect(peer)
            await asyncio.sleep(.03)
            assert peer.sessions and all(not x['authenticated'] for x in peer.sessions)
            assert peer.errors, 'Peer must reject c= bytes from a different certificate'
    asyncio.run(scenario())


def test_unsupported_hashless_certificate_has_clear_error():
    async def scenario():
        async with CertificatePeer('ed25519').serve() as peer:
            with pytest.raises((asyncpg.InterfaceError, asyncpg.PostgresError, ValueError)) as caught:
                await connect(peer)
            assert any(word in str(caught.value).lower() for word in ('certif', 'hash', 'digest', 'algorithm', 'channel'))
            assert all(not x['authenticated'] for x in peer.sessions)
    asyncio.run(scenario())
