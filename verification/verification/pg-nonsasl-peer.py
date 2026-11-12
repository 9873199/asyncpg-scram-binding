"""Independent trust/password/MD5 PostgreSQL peer for require-mode rejection."""
import asyncio
from contextlib import suppress
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys

spec = importlib.util.spec_from_file_location('pg_wire_peer_nonsasl_base', Path(__file__).with_name('pg-wire-peer.py'))
base = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = base
spec.loader.exec_module(base)


class NonSASLPeer(base.Peer):
    def __init__(self, *, auth_code, **kwargs):
        super().__init__(**kwargs)
        assert auth_code in (0, 3, 5)
        self.auth_code = auth_code

    async def client(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        session = {'authenticated': False, 'password_sent': False, 'auth_code': self.auth_code}
        self.sessions.append(session)
        try:
            size = struct.unpack('!I', await reader.readexactly(4))[0]
            startup = await reader.readexactly(size - 4)
            if size == 8 and startup == struct.pack('!I', 80877103):
                writer.write(b'S' if self.tls else b'N')
                await writer.drain()
                if self.tls:
                    await writer.start_tls(self.server_context, ssl_handshake_timeout=3)
                size = struct.unpack('!I', await reader.readexactly(4))[0]
                startup = await reader.readexactly(size - 4)
            assert startup[:4] == struct.pack('!I', 196608)
            if self.auth_code:
                salt = b'test'
                writer.write(base.authentication(self.auth_code, salt if self.auth_code == 5 else b''))
                await writer.drain()
                tag, response = await self.read_message(reader)
                session['password_sent'] = True
                assert tag == b'p'
                if self.auth_code == 3:
                    assert response == self.password + b'\0'
                else:
                    inner = hashlib.md5(self.password + b'local-test-user').hexdigest().encode('ascii')
                    expected = b'md5' + hashlib.md5(inner + salt).hexdigest().encode('ascii') + b'\0'
                    assert response == expected
            writer.write(base.authentication(0))
            for name, value in [(b'server_version', b'16.0'), (b'client_encoding', b'UTF8'), (b'integer_datetimes', b'on')]:
                writer.write(base.packet(b'S', name + b'\0' + value + b'\0'))
            writer.write(base.packet(b'K', struct.pack('!II', 12345, 6789)))
            writer.write(base.packet(b'Z', b'I'))
            await writer.drain()
            session['authenticated'] = True
            tag, response = await self.read_message(reader)
            assert tag == b'X'
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            self.errors.append(type(e).__name__ + ': ' + str(e))
        finally:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()
            self.tasks.discard(task)


if __name__ == '__main__':
    import asyncpg
    import json
    observations = []
    async def positive_controls():
        for tls in (False, True):
            for auth_code in (0, 3, 5):
                async with NonSASLPeer(auth_code=auth_code, tls=tls).serve() as p:
                    c = await asyncpg.connect(host='127.0.0.1', port=p.port, user='local-test-user',
                        password=p.password.decode(), database='test', ssl=p.client_context if tls else False, timeout=4)
                    await c.close()
                    await asyncio.sleep(.03)
                    assert not p.errors and p.sessions[0]['authenticated']
                    observations.append({'tls': tls, 'auth_code': auth_code, 'password_sent': p.sessions[0]['password_sent']})
    asyncio.run(positive_controls())
    print(json.dumps({'legacy_positive_controls': observations, 'external_database_used': False, 'password_content_logged': False}))
