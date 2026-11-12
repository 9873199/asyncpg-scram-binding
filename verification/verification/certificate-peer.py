"""Real TLS certificate variants for the independent PostgreSQL wire peer.

Keys are generated only inside the configured cache temp directory, never logged.
CERT_NONE here isolates binding-digest handling from PKI trust policy. The wire
peer still validates SCRAM client proof and channel-binding bytes independently.
"""
import asyncio
from contextlib import asynccontextmanager
import hashlib
import importlib.util
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import serialization

spec = importlib.util.spec_from_file_location('certificate_wire_peer', Path(__file__).with_name('pg-wire-peer.py'))
wire = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = wire
spec.loader.exec_module(wire)


class CertificatePeer(wire.Peer):
    def __init__(self, algorithm='sha256', *, mismatch=False, mechanisms=None):
        super().__init__()
        self.algorithm = algorithm
        self.mismatch = mismatch
        if mechanisms is not None:
            self.mechanisms = mechanisms

    def configure(self):
        cache = Path(os.environ['TEMP']).resolve()
        assert cache.is_relative_to(Path(r'D:\hc\userFeedback\cache').resolve())
        self.tmp = tempfile.TemporaryDirectory(prefix='scram-cert-', dir=cache)
        directory = Path(self.tmp.name)
        config = directory / 'openssl.cnf'
        config.write_text('[req]\ndistinguished_name = dn\n[dn]\n', encoding='ascii')
        key = directory / 'key.pem'
        cert = directory / 'cert.pem'
        executable = os.environ.get('UF_TEST_OPENSSL', r'D:\Program Files\Git\usr\bin\openssl.exe')
        command = [executable, 'req', '-config', str(config), '-x509', '-newkey',
                   'ed25519' if self.algorithm == 'ed25519' else 'rsa:2048',
                   '-noenc', '-keyout', str(key), '-out', str(cert), '-days', '1',
                   '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1']
        if self.algorithm != 'ed25519':
            command.append('-' + self.algorithm)
        result = subprocess.run(command, capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError('Certificate fixture generation failed: ' + result.stderr.decode(errors='replace'))
        parsed = x509.load_pem_x509_certificate(cert.read_bytes())
        self.der = parsed.public_bytes(serialization.Encoding.DER)
        expected_hash = 'sha256' if self.algorithm in ('md5', 'sha1', 'ed25519') else self.algorithm
        self.binding = hashlib.new(expected_hash, self.der).digest()
        if self.mismatch:
            self.binding = bytes([self.binding[0] ^ 1]) + self.binding[1:]
        self.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_context.set_ciphers('DEFAULT:@SECLEVEL=0')
        self.server_context.load_cert_chain(str(cert), str(key))
        self.client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.client_context.check_hostname = False
        self.client_context.verify_mode = ssl.CERT_NONE
        self.client_context.set_ciphers('DEFAULT:@SECLEVEL=0')

    @asynccontextmanager
    async def serve(self):
        try:
            async with super().serve() as server:
                yield server
        finally:
            if hasattr(self, 'tmp'):
                self.tmp.cleanup()


if __name__ == '__main__':
    import asyncpg

    async def control():
        for algorithm in ('sha256', 'sha384', 'sha512', 'sha1', 'md5', 'ed25519'):
            async with CertificatePeer(algorithm, mechanisms=(b'SCRAM-SHA-256',)).serve() as peer:
                connection = await asyncpg.connect(host='127.0.0.1', port=peer.port,
                    user='local-test-user', password=peer.password.decode(), database='test',
                    ssl=peer.client_context, timeout=4)
                await connection.close()
                await asyncio.sleep(.03)
                assert not peer.errors and peer.sessions[0]['authenticated'], peer.errors
                print('PASS ordinary SCRAM with actual ' + algorithm + ' certificate over TLS')

    asyncio.run(control())
