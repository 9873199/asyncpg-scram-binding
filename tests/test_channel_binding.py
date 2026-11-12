# Copyright (C) 2016-present the asyncpg authors and contributors
# <see AUTHORS file>
#
# This module is part of asyncpg and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


"""Tests for SCRAM-SHA-256-PLUS channel binding.

These tests do not require a running PostgreSQL cluster.  Instead they
implement a minimal, in-process PostgreSQL protocol peer that:

* terminates a real TLS connection with an ephemeral certificate,
* drives the SASL/SCRAM authentication exchange,
* recomputes the SCRAM proof and server signature from the raw bytes the
  asyncpg client put on the wire, and
* checks the ``c=`` attribute against the RFC 5929 tls-server-end-point
  hash of the certificate of the exact TLS channel.

Deterministic nonces are obtained by pinning the Cython SCRAM module's
nonce source, so the full transcript (mechanism choice, GS2 header,
channel binding, proof) can be compared against an independent reference
computation.
"""

import asyncio
import base64
import contextlib
import datetime
import hashlib
import hmac
import ipaddress
import os
import socket
import ssl
import struct
import socketserver
import tempfile
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import asyncpg
from asyncpg import exceptions
from asyncpg import _channel_binding as cb
from asyncpg.protocol import protocol as pg_protocol
from asyncpg.protocol.protocol import SCRAMAuthentication


PASSWORD = 'pencil'
USERNAME = 'scram_user'
DATABASE = 'scram_db'
SALT_B64 = b'W22ZaJ0SNY7soEsUEjb6gQ=='
ITERATIONS = 4096

# Deterministic client nonce: base64 of 24 zero bytes.
FIXED_NONCE = base64.b64encode(b'\x00' * 24)
SERVER_NONCE_SUFFIX = b'QUJDREVGR0hJSktMTU5PUA'

MECH_PLAIN = b'SCRAM-SHA-256'
MECH_PLUS = b'SCRAM-SHA-256-PLUS'


# ---------------------------------------------------------------------------
# DER / certificate helpers
# ---------------------------------------------------------------------------

def _der_length(length):
    if length < 0x80:
        return bytes([length])
    out = b''
    while length:
        out = bytes([length & 0xff]) + out
        length >>= 8
    return bytes([0x80 | len(out)]) + out


def _tlv(tag, content):
    return bytes([tag]) + _der_length(len(content)) + content


def _der_oid(arc):
    parts = [int(x) for x in arc.split('.')]
    body = bytes([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7f]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7f))
            part >>= 7
        body += bytes(reversed(chunk))
    return _tlv(0x06, body)


_NULL = b'\x05\x00'


def _algorithm_id(oid_arc):
    return _tlv(0x30, _der_oid(oid_arc) + _NULL)


def _distinguished_name(common_name):
    attribute = _tlv(
        0x30,
        _der_oid('2.5.4.3') + _tlv(0x0c, common_name.encode('ascii')))
    return _tlv(0x30, _tlv(0x31, attribute))


def _weak_signed_certificate(private_key, sig_oid, hash_alg, common_name):
    """Build a certificate signed with a legacy digest (MD5 / SHA-1).

    The high-level cryptography x509 builder refuses these digests, so the
    certificate is assembled from raw DER and signed with the low-level
    primitives (which still permit them).  The resulting object parses
    normally and reports the legacy signature hash.
    """
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    name = _distinguished_name(common_name)
    validity = _tlv(
        0x30,
        _tlv(0x17, b'250101000000Z') + _tlv(0x17, b'300101000000Z'))
    tbs = _tlv(
        0x30,
        _tlv(0x02, b'\x01') + _algorithm_id(sig_oid) + name +
        validity + name + spki)
    signature = private_key.sign(
        tbs, padding.PKCS1v15(), hash_alg())
    return x509.load_der_x509_certificate(
        _tlv(0x30, tbs + _algorithm_id(sig_oid) +
             _tlv(0x03, b'\x00' + signature)))


def _unknown_algorithm_certificate(private_key, common_name='unknown'):
    # A syntactically valid certificate carrying an unrecognized signature
    # algorithm OID; cryptography cannot name its digest.
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    name = _distinguished_name(common_name)
    validity = _tlv(
        0x30,
        _tlv(0x17, b'250101000000Z') + _tlv(0x17, b'300101000000Z'))
    bogus_oid = '1.2.3.4.567.8.9'
    tbs = _tlv(
        0x30,
        _tlv(0x02, b'\x07') + _algorithm_id(bogus_oid) + name +
        validity + name + spki)
    return x509.load_der_x509_certificate(
        _tlv(0x30, tbs + _algorithm_id(bogus_oid) +
             _tlv(0x03, b'\x00' + b'\x00' * 256)))


def _standard_certificate(private_key, hash_alg, common_name):
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2025, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),
            critical=False)
        .sign(private_key, hash_alg())
    )


def _ed25519_certificate(private_key, common_name):
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2025, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .sign(private_key, None)
    )


def _cert_der(certificate):
    return certificate.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# Independent SCRAM reference implementation (RFC 5802 / RFC 7677)
# ---------------------------------------------------------------------------

def _xor(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def _hi(password, salt, iterations):
    return hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), salt, iterations)


def reference_server_keys(password, salt_b64, iterations):
    salted = _hi(password, base64.b64decode(salt_b64), iterations)
    client_key = hmac.new(salted, b'Client Key', hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b'Server Key', hashlib.sha256).digest()
    return client_key, stored_key, server_key


def reference_proof(auth_message, client_key, stored_key):
    signature = hmac.new(
        stored_key, auth_message, hashlib.sha256).digest()
    return _xor(client_key, signature)


def reference_server_signature(auth_message, server_key):
    return hmac.new(
        server_key, auth_message, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Minimal PostgreSQL protocol peer
# ---------------------------------------------------------------------------

def _frame(message_type, payload):
    return message_type + struct.pack('!I', len(payload) + 4) + payload


def _auth_frame(auth_type, payload=b''):
    return _frame(b'R', struct.pack('!I', auth_type) + payload)


def _error_frame(sqlstate, message):
    payload = (
        b'SFATAL\x00'
        b'C' + sqlstate.encode('ascii') + b'\x00'
        b'M' + message.encode('utf-8') + b'\x00'
        b'\x00')
    return _frame(b'E', payload)


def _recv_exact(sock, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError('peer closed the connection')
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


class _SCRAMPeerSession:
    """Blocking-socket implementation of the PostgreSQL SASL exchange.

    Runs on a worker thread behind a threaded TCP server, so it exercises a
    real TLS channel without depending on the event loop's (platform
    dependent) server-side ``start_tls`` data delivery.
    """

    SSL_REQUEST = struct.pack('!II', 8, 80877103)

    def __init__(self, config, ssl_context, starttls, tls):
        self._config = config
        self._ssl_context = ssl_context
        self._starttls = starttls
        self._tls = tls
        self._sock = None
        self._server_first = None
        self._client_first_bare = None
        self.observed = config.observed

    def run(self, raw_socket):
        if not self._tls:
            # Plaintext peer: no SSLRequest and no TLS wrapping.
            self._sock = raw_socket
        elif self._starttls:
            request = _recv_exact(raw_socket, 8)
            if request != self.SSL_REQUEST:
                raise AssertionError(
                    'expected an SSLRequest, got {!r}'.format(request))
            raw_socket.sendall(b'S')
            self._sock = self._ssl_context.wrap_socket(
                raw_socket, server_side=True)
        else:
            # Direct TLS: the connection is already TLS on accept.
            self._sock = self._ssl_context.wrap_socket(
                raw_socket, server_side=True)
        self._read_startup_packet()
        if self._config.cleartext_password:
            # AuthenticationCleartextPassword
            self._sock.sendall(_auth_frame(3))
            return
        if self._config.md5_password:
            # AuthenticationMD5Password carries a four-byte salt.
            self._sock.sendall(_auth_frame(5, b'\x01\x02\x03\x04'))
            return
        self._run_sasl_exchange()
        self._drain_until_terminate()

    def _read_startup_packet(self):
        # The startup packet has no message type.
        length = struct.unpack('!I', _recv_exact(self._sock, 4))[0]
        _recv_exact(self._sock, length - 4)

    def _read_message(self):
        header = _recv_exact(self._sock, 5)
        message_type = header[:1]
        length = struct.unpack('!I', header[1:])[0]
        payload = _recv_exact(self._sock, length - 4)
        return message_type, payload

    def _run_sasl_exchange(self):
        self._send_sasl_request()
        message_type, payload = self._read_message()
        assert message_type == b'p'
        self._handle_sasl_initial(payload)
        message_type, payload = self._read_message()
        assert message_type == b'p'
        self._handle_sasl_response(payload)

    def _send_sasl_request(self):
        payload = b''.join(
            mechanism + b'\x00'
            for mechanism in self._config.mechanisms) + b'\x00'
        self._sock.sendall(_auth_frame(10, payload))

    def _handle_sasl_initial(self, payload):
        mechanism, rest = payload.split(b'\x00', 1)
        response_length = struct.unpack('!I', rest[:4])[0]
        response = rest[4:4 + response_length]
        gs2_header, self._client_first_bare = response.split(b',,', 1)
        self.observed['mechanism'] = mechanism
        self.observed['gs2_header'] = gs2_header + b',,'
        expected_nonce = self._extract_attribute(
            self._client_first_bare, b'r')
        server_nonce = expected_nonce + SERVER_NONCE_SUFFIX
        self._server_first = (
            b'r=' + server_nonce +
            b',s=' + SALT_B64 +
            b',i=' + str(ITERATIONS).encode('ascii'))
        self._sock.sendall(_auth_frame(11, self._server_first))

    def _handle_sasl_response(self, payload):
        c_field, nonce_field, proof_field = payload.split(b',')
        channel_binding = base64.b64decode(c_field[2:])
        self.observed['channel_binding'] = channel_binding
        self.observed['nonce'] = nonce_field[2:]
        proof = base64.b64decode(proof_field[2:])
        self._validate_channel_binding(channel_binding)
        auth_message = self._build_auth_message(c_field, nonce_field)
        if not self._verify_proof(auth_message, proof):
            self._sock.sendall(
                _error_frame('28P01', 'password authentication failed'))
            return
        self._send_final(auth_message)

    def _validate_channel_binding(self, channel_binding):
        mechanism = self.observed['mechanism']
        if mechanism == MECH_PLUS:
            expected = (
                b'p=tls-server-end-point,,' + self._config.end_point)
        else:
            expected = b'n,,'
        self.observed['binding_matches_channel'] = (
            channel_binding == expected)
        if not self.observed['binding_matches_channel']:
            raise AssertionError(
                'client c= does not match the TLS channel binding')

    def _build_auth_message(self, c_field, nonce_field):
        client_final_without_proof = c_field + b',' + nonce_field
        return (
            self._client_first_bare + b',' +
            self._server_first + b',' +
            client_final_without_proof)

    def _verify_proof(self, auth_message, proof):
        client_key, stored_key, _ = reference_server_keys(
            PASSWORD, SALT_B64, ITERATIONS)
        expected = reference_proof(auth_message, client_key, stored_key)
        self.observed['proof_valid'] = hmac.compare_digest(
            proof, expected)
        return self.observed['proof_valid']

    def _send_final(self, auth_message):
        _, _, server_key = reference_server_keys(
            PASSWORD, SALT_B64, ITERATIONS)
        signature = reference_server_signature(auth_message, server_key)
        if self._config.tamper_server_signature:
            signature = bytes(reversed(signature))
            self._sock.sendall(
                _auth_frame(12, b'v=' + base64.b64encode(signature)))
            return
        self._sock.sendall(
            _auth_frame(12, b'v=' + base64.b64encode(signature)))
        self._sock.sendall(_auth_frame(0))
        self._sock.sendall(self._parameter_status(
            'server_version', '16.0'))
        self._sock.sendall(self._parameter_status(
            'client_encoding', 'UTF8'))
        self._sock.sendall(self._parameter_status(
            'integer_datetimes', 'on'))
        self._sock.sendall(
            _frame(b'K', struct.pack('!II', 1234, 5678)))
        self._sock.sendall(_frame(b'Z', b'I'))

    def _parameter_status(self, name, value):
        return _frame(
            b'S',
            name.encode('ascii') + b'\x00' +
            value.encode('ascii') + b'\x00')

    def _drain_until_terminate(self):
        try:
            while True:
                message_type, payload = self._read_message()
                if message_type == b'X':
                    return
                if message_type == b'Q':
                    # SimpleQuery (e.g. the pool's "RESET ALL" on release).
                    self._answer_simple_query(payload)
        except (ConnectionError, OSError):
            # The client closed after the test finished; that is fine.
            return

    def _answer_simple_query(self, payload):
        # The query string is a single null-terminated value.
        _ = payload.rstrip(b'\x00')
        self._sock.sendall(_frame(b'C', b'RESET\x00'))
        self._sock.sendall(_frame(b'Z', b'I'))

    def _extract_attribute(self, message, attribute):
        prefix = attribute + b'='
        for part in message.split(b','):
            if part.startswith(prefix):
                return part[len(prefix):]
        raise AssertionError(
            'missing attribute {!r}'.format(attribute))


class _ThreadedSCRAMServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, config, ssl_context, starttls, tls):
        self.config = config
        self.ssl_context = ssl_context
        self.starttls = starttls
        self.tls = tls
        super().__init__(address, _SCRAMRequestHandler)
        self._thread = threading.Thread(
            target=self.serve_forever, daemon=True)
        self._thread.start()


class _SCRAMRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):
        # Bound blocking reads so a peer that disconnects without sending
        # Terminate cannot pin the handler thread (and server shutdown)
        # forever.
        self.request.settimeout(15)
        session = _SCRAMPeerSession(
            self.server.config, self.server.ssl_context,
            self.server.starttls, self.server.tls)
        try:
            session.run(self.request)
        except (ConnectionError, OSError, AssertionError, socket.timeout):
            # The client intentionally aborts on several negative paths.
            pass
        finally:
            if session._sock is not None:
                with contextlib.suppress(OSError):
                    session._sock.close()
            else:
                with contextlib.suppress(OSError):
                    self.request.close()


class ServerConfig:

    def __init__(self, certificate, mechanisms, *,
                 cleartext_password=False,
                 md5_password=False,
                 tamper_server_signature=False):
        self.certificate = certificate
        self.end_point = cb.get_tls_server_end_point(
            _StaticSSLObject(_cert_der(certificate)))
        self.mechanisms = mechanisms
        self.cleartext_password = cleartext_password
        self.md5_password = md5_password
        self.tamper_server_signature = tamper_server_signature
        self.observed = {}

    def server_context(self, cert_path, key_path):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        return context


class _StaticSSLObject:
    """Stand-in for an asyncio ssl_object with a fixed leaf certificate."""

    def __init__(self, leaf_der):
        self._leaf = leaf_der

    def get_unverified_chain(self):
        return [self._leaf]

    def get_verified_chain(self):
        return [self._leaf]

    def getpeercert(self, binary_form=False):
        return self._leaf if binary_form else {}


class FakeSCRAMHost:
    """Binds a threaded server backed by an ephemeral certificate."""

    def __init__(self, config, private_key, *, starttls=False, tls=True):
        self._config = config
        self._key = private_key
        self._starttls = starttls
        self._tls = tls
        self._server = None
        self._cert_path = None
        self._key_path = None
        self._tmpdir = None

    def _write_cert_files(self):
        self._tmpdir = tempfile.mkdtemp()
        self._cert_path = os.path.join(self._tmpdir, 'server.crt')
        self._key_path = os.path.join(self._tmpdir, 'server.key')
        with open(self._cert_path, 'wb') as f:
            f.write(self._config.certificate.public_bytes(
                serialization.Encoding.PEM))
        with open(self._key_path, 'wb') as f:
            f.write(self._key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))

    async def start(self):
        await asyncio.get_event_loop().run_in_executor(
            None, self._start_blocking)
        return self._server.server_address[1]

    def _start_blocking(self):
        ssl_context = None
        if self._tls:
            self._write_cert_files()
            ssl_context = self._config.server_context(
                self._cert_path, self._key_path)
        self._server = _ThreadedSCRAMServer(
            ('127.0.0.1', 0), self._config, ssl_context,
            self._starttls, self._tls)

    async def close(self):
        if self._server is not None:
            await asyncio.get_event_loop().run_in_executor(
                None, self._server.shutdown)
            self._server.server_close()


def _client_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


@contextlib.contextmanager
def fixed_client_nonce():
    original = pg_protocol.secrets.token_bytes
    pg_protocol.secrets.token_bytes = lambda n: b'\x00' * n
    try:
        yield
    finally:
        pg_protocol.secrets.token_bytes = original


# ---------------------------------------------------------------------------
# Unit tests: GS2 headers and c= content
# ---------------------------------------------------------------------------

class TestSCRAMChannelBindingMessages(unittest.TestCase):

    def test_plain_scram_keeps_n_gs2_header(self):
        scram = SCRAMAuthentication(MECH_PLAIN)
        self.assertEqual(scram.client_channel_binding, b'n,,')
        self.assertIsNone(scram.channel_binding_data)

    def test_plus_uses_tls_server_end_point_header(self):
        binding = b'\xaa' * 32
        scram = SCRAMAuthentication(MECH_PLUS, binding)
        self.assertEqual(
            scram.client_channel_binding, b'p=tls-server-end-point,,')
        self.assertEqual(scram.channel_binding_data, binding)

    def test_unknown_mechanism_rejected(self):
        with self.assertRaises(exceptions.InterfaceError):
            SCRAMAuthentication(b'SCRAM-SHA-256-MADEUP')

    def test_header_builder(self):
        self.assertEqual(cb.build_channel_binding_header(None), b'n,,')
        self.assertEqual(
            cb.build_channel_binding_header(b'x'),
            b'p=tls-server-end-point,,')


# ---------------------------------------------------------------------------
# Unit tests: tls-server-end-point computation (RFC 5929)
# ---------------------------------------------------------------------------

class TestTLSServerEndPoint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rsa_key = rsa.generate_private_key(65537, 2048)

    def test_sha256_certificate_uses_sha256(self):
        cert = _standard_certificate(
            self.rsa_key, hashes.SHA256, 'sha256')
        der = _cert_der(cert)
        self.assertEqual(
            cb.get_tls_server_end_point(_StaticSSLObject(der)),
            hashlib.sha256(der).digest())

    def test_sha384_certificate_uses_sha384(self):
        cert = _standard_certificate(
            self.rsa_key, hashes.SHA384, 'sha384')
        der = _cert_der(cert)
        self.assertEqual(
            cb.get_tls_server_end_point(_StaticSSLObject(der)),
            hashlib.sha384(der).digest())

    def test_sha1_certificate_falls_back_to_sha256(self):
        cert = _weak_signed_certificate(
            self.rsa_key, '1.2.840.113549.1.1.5', hashes.SHA1, 'sha1')
        self.assertEqual(cert.signature_hash_algorithm.name, 'sha1')
        der = _cert_der(cert)
        binding = cb.get_tls_server_end_point(_StaticSSLObject(der))
        self.assertEqual(binding, hashlib.sha256(der).digest())
        self.assertNotEqual(binding, hashlib.sha1(der).digest())

    def test_md5_certificate_falls_back_to_sha256(self):
        cert = _weak_signed_certificate(
            self.rsa_key, '1.2.840.113549.1.1.4', hashes.MD5, 'md5')
        self.assertEqual(cert.signature_hash_algorithm.name, 'md5')
        der = _cert_der(cert)
        binding = cb.get_tls_server_end_point(_StaticSSLObject(der))
        self.assertEqual(binding, hashlib.sha256(der).digest())

    def test_ed25519_certificate_uses_sha256(self):
        key = ed25519.Ed25519PrivateKey.generate()
        cert = _ed25519_certificate(key, 'ed25519')
        self.assertIsNone(cert.signature_hash_algorithm)
        der = _cert_der(cert)
        self.assertEqual(
            cb.get_tls_server_end_point(_StaticSSLObject(der)),
            hashlib.sha256(der).digest())

    def test_unknown_signature_algorithm_is_a_clear_error(self):
        cert = _unknown_algorithm_certificate(self.rsa_key)
        with self.assertRaises(exceptions.InterfaceError) as cm:
            cb.get_tls_server_end_point(
                _StaticSSLObject(_cert_der(cert)))
        self.assertIn('channel binding', str(cm.exception))

    def test_non_tls_object_is_a_clear_error(self):
        with self.assertRaises(exceptions.InterfaceError):
            cb.get_tls_server_end_point(None)

    def test_missing_certificate_is_a_clear_error(self):
        class EmptySSLObject:
            def get_unverified_chain(self):
                return []

            def get_verified_chain(self):
                return []

            def getpeercert(self, binary_form=False):
                return None

        with self.assertRaises(exceptions.InterfaceError):
            cb.get_tls_server_end_point(EmptySSLObject())

    def test_binary_form_getpeercert_fallback(self):
        cert = _standard_certificate(
            self.rsa_key, hashes.SHA256, 'fallback')
        der = _cert_der(cert)

        class BinaryFormOnly:
            def getpeercert(self, binary_form=False):
                return der if binary_form else {}

        self.assertEqual(
            cb.get_tls_server_end_point(BinaryFormOnly()),
            hashlib.sha256(der).digest())


# ---------------------------------------------------------------------------
# Unit tests: mechanism negotiation matrix
# ---------------------------------------------------------------------------

class TestMechanismNegotiation(unittest.TestCase):

    def setUp(self):
        self.binding = b'\x01' * 32
        self.ssl_object = _StaticSSLObject(b'cert-der')
        self._real_extractor = cb.get_channel_binding_data
        cb.get_channel_binding_data = lambda ssl_object: self.binding
        self.addCleanup(self._restore)

    def _restore(self):
        cb.get_channel_binding_data = self._real_extractor

    def test_disable_never_uses_plus(self):
        mechanism, data, plus = cb.get_scram_mechanisms(
            [MECH_PLAIN, MECH_PLUS], cb.ChannelBindingMode.disable,
            self.ssl_object)
        self.assertEqual(mechanism, MECH_PLAIN)
        self.assertIsNone(data)
        self.assertFalse(plus)

    def test_prefer_selects_plus_when_everything_supports_it(self):
        mechanism, data, plus = cb.get_scram_mechanisms(
            [MECH_PLAIN, MECH_PLUS], cb.ChannelBindingMode.prefer,
            self.ssl_object)
        self.assertEqual(mechanism, MECH_PLUS)
        self.assertEqual(data, self.binding)
        self.assertTrue(plus)

    def test_prefer_downgrades_with_gs2_signal_when_no_plus(self):
        mechanism, data, plus = cb.get_scram_mechanisms(
            [MECH_PLAIN], cb.ChannelBindingMode.prefer, self.ssl_object)
        self.assertEqual(mechanism, MECH_PLAIN)
        self.assertIsNone(data)
        self.assertFalse(plus)

    def test_prefer_downgrades_without_tls(self):
        mechanism, data, plus = cb.get_scram_mechanisms(
            [MECH_PLAIN, MECH_PLUS], cb.ChannelBindingMode.prefer, None)
        self.assertEqual(mechanism, MECH_PLAIN)
        self.assertIsNone(data)
        self.assertFalse(plus)

    def test_require_selects_plus(self):
        mechanism, data, plus = cb.get_scram_mechanisms(
            [MECH_PLAIN, MECH_PLUS], cb.ChannelBindingMode.require,
            self.ssl_object)
        self.assertEqual(mechanism, MECH_PLUS)
        self.assertEqual(data, self.binding)
        self.assertTrue(plus)

    def test_require_rejects_non_tls(self):
        with self.assertRaises(exceptions.InterfaceError):
            cb.get_scram_mechanisms(
                [MECH_PLAIN, MECH_PLUS],
                cb.ChannelBindingMode.require, None)

    def test_require_rejects_server_without_plus(self):
        with self.assertRaises(exceptions.InterfaceError) as cm:
            cb.get_scram_mechanisms(
                [MECH_PLAIN], cb.ChannelBindingMode.require,
                self.ssl_object)
        self.assertIn('SCRAM-SHA-256-PLUS', str(cm.exception))

    def test_require_rejects_missing_binding_data(self):
        def broken(ssl_object):
            raise exceptions.InterfaceError('no end point')

        cb.get_channel_binding_data = broken
        with self.assertRaises(exceptions.InterfaceError):
            cb.get_scram_mechanisms(
                [MECH_PLAIN, MECH_PLUS], cb.ChannelBindingMode.require,
                self.ssl_object)

    def test_mode_parsing(self):
        self.assertIs(
            cb.ChannelBindingMode.parse(None),
            cb.ChannelBindingMode.disable)
        self.assertIs(
            cb.ChannelBindingMode.parse('require'),
            cb.ChannelBindingMode.require)
        self.assertIs(
            cb.ChannelBindingMode.parse(cb.ChannelBindingMode.prefer),
            cb.ChannelBindingMode.prefer)
        with self.assertRaises(exceptions.ClientConfigurationError):
            cb.ChannelBindingMode.parse('sometimes')


# ---------------------------------------------------------------------------
# End-to-end tests against the fake PostgreSQL peer over real TLS
# ---------------------------------------------------------------------------

class TestSCRAMPlusOverTLS(unittest.IsolatedAsyncioTestCase):

    @classmethod
    def setUpClass(cls):
        cls.rsa_key = rsa.generate_private_key(65537, 2048)
        cls.certificate = _standard_certificate(
            cls.rsa_key, hashes.SHA256, 'localhost')

    def _make_host(self, mechanisms, *, starttls=True, tls=True, **kwargs):
        config = ServerConfig(self.certificate, mechanisms, **kwargs)
        return FakeSCRAMHost(
            config, self.rsa_key, starttls=starttls, tls=tls), config

    async def _connect(self, port, **kwargs):
        options = dict(
            host='127.0.0.1', port=port, user=USERNAME, password=PASSWORD,
            database=DATABASE, ssl=_client_ssl_context(),
            channel_binding='disable')
        options.update(kwargs)
        return await asyncpg.connect(**options)

    async def test_require_plus_happy_path(self):
        host, config = self._make_host([MECH_PLAIN, MECH_PLUS])
        port = await host.start()
        try:
            with fixed_client_nonce():
                con = await self._connect(port, channel_binding='require')
            try:
                self.assertEqual(
                    config.observed['mechanism'], MECH_PLUS)
                self.assertEqual(
                    config.observed['gs2_header'],
                    b'p=tls-server-end-point,,')
                self.assertTrue(
                    config.observed['binding_matches_channel'])
                self.assertTrue(config.observed['proof_valid'])
                self.assertEqual(
                    config.observed['nonce'],
                    FIXED_NONCE + SERVER_NONCE_SUFFIX)
            finally:
                await con.close()
        finally:
            await host.close()

    async def test_client_c_attribute_matches_reference(self):
        host, config = self._make_host([MECH_PLUS])
        port = await host.start()
        try:
            con = await self._connect(port, channel_binding='require')
            try:
                expected_end_point = cb.get_tls_server_end_point(
                    _StaticSSLObject(_cert_der(self.certificate)))
                self.assertEqual(
                    config.observed['channel_binding'],
                    b'p=tls-server-end-point,,' + expected_end_point)
            finally:
                await con.close()
        finally:
            await host.close()

    async def test_prefer_uses_plus_when_advertised(self):
        host, config = self._make_host([MECH_PLAIN, MECH_PLUS])
        port = await host.start()
        try:
            con = await self._connect(port, channel_binding='prefer')
            try:
                self.assertEqual(
                    config.observed['mechanism'], MECH_PLUS)
            finally:
                await con.close()
        finally:
            await host.close()

    async def test_prefer_falls_back_to_plain_scram(self):
        host, config = self._make_host([MECH_PLAIN])
        port = await host.start()
        try:
            con = await self._connect(port, channel_binding='prefer')
            try:
                self.assertEqual(
                    config.observed['mechanism'], MECH_PLAIN)
                self.assertEqual(
                    config.observed['gs2_header'], b'n,,')
                self.assertEqual(
                    config.observed['channel_binding'], b'n,,')
                self.assertTrue(config.observed['proof_valid'])
            finally:
                await con.close()
        finally:
            await host.close()

    async def test_disable_keeps_plain_scram_regression(self):
        host, config = self._make_host([MECH_PLAIN, MECH_PLUS])
        port = await host.start()
        try:
            con = await self._connect(port)
            try:
                self.assertEqual(
                    config.observed['mechanism'], MECH_PLAIN)
                self.assertEqual(
                    config.observed['gs2_header'], b'n,,')
                self.assertTrue(config.observed['proof_valid'])
            finally:
                await con.close()
        finally:
            await host.close()

    async def test_require_rejects_plain_only_server(self):
        host, _ = self._make_host([MECH_PLAIN])
        port = await host.start()
        try:
            with self.assertRaises(exceptions.InterfaceError) as cm:
                await self._connect(port, channel_binding='require')
            self.assertIn('SCRAM-SHA-256-PLUS', str(cm.exception))
        finally:
            await host.close()

    async def test_require_rejects_cleartext_password(self):
        host, _ = self._make_host(
            [MECH_PLAIN, MECH_PLUS], cleartext_password=True)
        port = await host.start()
        try:
            with self.assertRaises(exceptions.InterfaceError) as cm:
                await self._connect(port, channel_binding='require')
            self.assertIn('channel_binding=require', str(cm.exception))
        finally:
            await host.close()

    async def test_require_rejects_md5_password(self):
        host, _ = self._make_host(
            [MECH_PLAIN, MECH_PLUS], md5_password=True)
        port = await host.start()
        try:
            with self.assertRaises(exceptions.InterfaceError) as cm:
                await self._connect(port, channel_binding='require')
            self.assertIn('channel_binding=require', str(cm.exception))
            self.assertIn('MD5 password', str(cm.exception))
        finally:
            await host.close()

    async def test_bad_server_signature_fails(self):
        host, _ = self._make_host(
            [MECH_PLUS], tamper_server_signature=True)
        port = await host.start()
        try:
            with self.assertRaises(exceptions.InterfaceError) as cm:
                await self._connect(port, channel_binding='require')
            self.assertIn('server signature', str(cm.exception))
        finally:
            await host.close()

    async def test_bad_password_is_rejected(self):
        host, _ = self._make_host([MECH_PLUS])
        port = await host.start()
        try:
            with self.assertRaises(exceptions.InvalidPasswordError):
                await self._connect(
                    port, channel_binding='require',
                    password='wrong-password')
        finally:
            await host.close()

    async def test_prefer_downgrades_without_tls_on_the_wire(self):
        # A plaintext peer forces the GS2 "n,," negotiated downgrade; the
        # client must never send a PLUS mechanism over a non-TLS channel.
        host, config = self._make_host(
            [MECH_PLAIN, MECH_PLUS], starttls=False, tls=False)
        port = await host.start()
        try:
            con = await asyncpg.connect(
                host='127.0.0.1', port=port, user=USERNAME,
                password=PASSWORD, database=DATABASE, ssl=False,
                channel_binding='prefer')
            try:
                self.assertEqual(
                    config.observed['mechanism'], MECH_PLAIN)
                self.assertEqual(
                    config.observed['gs2_header'], b'n,,')
                self.assertTrue(config.observed['proof_valid'])
            finally:
                await con.close()
        finally:
            await host.close()

    async def test_require_plus_over_direct_tls(self):
        # Direct TLS (PG17 sslnegotiation=direct) binds the channel too.
        host, config = self._make_host(
            [MECH_PLAIN, MECH_PLUS], starttls=False)
        port = await host.start()
        try:
            con = await self._connect(
                port, channel_binding='require', direct_tls=True)
            try:
                self.assertEqual(
                    config.observed['mechanism'], MECH_PLUS)
                self.assertTrue(
                    config.observed['binding_matches_channel'])
            finally:
                await con.close()
        finally:
            await host.close()

    async def test_dsn_carries_channel_binding(self):
        host, config = self._make_host([MECH_PLAIN, MECH_PLUS])
        port = await host.start()
        try:
            dsn = (
                'postgresql://{}:{}@127.0.0.1:{}/{}'
                '?sslmode=require&channel_binding=require'
            ).format(USERNAME, PASSWORD, port, DATABASE)
            con = await asyncpg.connect(
                dsn, ssl=_client_ssl_context())
            try:
                self.assertEqual(
                    config.observed['mechanism'], MECH_PLUS)
            finally:
                await con.close()
        finally:
            await host.close()

    async def test_pool_carries_channel_binding(self):
        host, config = self._make_host([MECH_PLAIN, MECH_PLUS])
        port = await host.start()
        try:
            pool = await asyncpg.create_pool(
                host='127.0.0.1', port=port, user=USERNAME,
                password=PASSWORD, database=DATABASE,
                ssl=_client_ssl_context(),
                channel_binding='require',
                min_size=1, max_size=1)
            try:
                async with pool.acquire() as con:
                    self.assertEqual(
                        config.observed['mechanism'], MECH_PLUS)
                    self.assertTrue(
                        config.observed['binding_matches_channel'])
                    self.assertTrue(config.observed['proof_valid'])
                    # A pooled connection is a live, connected proxy.
                    self.assertFalse(con.is_closed())
            finally:
                await pool.close()
        finally:
            await host.close()


class TestChannelIsolation(unittest.IsolatedAsyncioTestCase):

    async def test_two_concurrent_connections_bind_different_certs(self):
        key_a = rsa.generate_private_key(65537, 2048)
        key_b = rsa.generate_private_key(65537, 2048)
        cert_a = _standard_certificate(key_a, hashes.SHA256, 'cert-a')
        cert_b = _standard_certificate(key_b, hashes.SHA256, 'cert-b')
        config_a = ServerConfig(cert_a, [MECH_PLUS])
        config_b = ServerConfig(cert_b, [MECH_PLUS])
        host_a = FakeSCRAMHost(config_a, key_a, starttls=True)
        host_b = FakeSCRAMHost(config_b, key_b, starttls=True)
        port_a = await host_a.start()
        port_b = await host_b.start()

        async def connect(port):
            return await asyncpg.connect(
                host='127.0.0.1', port=port, user=USERNAME,
                password=PASSWORD, database=DATABASE,
                ssl=_client_ssl_context(), channel_binding='require')

        try:
            con_a, con_b = await asyncio.gather(
                connect(port_a), connect(port_b))
            try:
                end_point_a = cb.get_tls_server_end_point(
                    _StaticSSLObject(_cert_der(cert_a)))
                end_point_b = cb.get_tls_server_end_point(
                    _StaticSSLObject(_cert_der(cert_b)))
                self.assertNotEqual(end_point_a, end_point_b)
                self.assertEqual(
                    config_a.observed['channel_binding'],
                    b'p=tls-server-end-point,,' + end_point_a)
                self.assertEqual(
                    config_b.observed['channel_binding'],
                    b'p=tls-server-end-point,,' + end_point_b)
                self.assertTrue(config_a.observed['proof_valid'])
                self.assertTrue(config_b.observed['proof_valid'])
            finally:
                await asyncio.gather(con_a.close(), con_b.close())
        finally:
            await host_a.close()
            await host_b.close()

    async def test_sequential_connections_do_not_share_binding(self):
        first_key = rsa.generate_private_key(65537, 2048)
        second_key = rsa.generate_private_key(65537, 2048)
        first_cert = _standard_certificate(
            first_key, hashes.SHA256, 'first')
        second_cert = _standard_certificate(
            second_key, hashes.SHA256, 'second')
        first_config = ServerConfig(first_cert, [MECH_PLUS])
        second_config = ServerConfig(second_cert, [MECH_PLUS])
        first_host = FakeSCRAMHost(
            first_config, first_key, starttls=True)
        second_host = FakeSCRAMHost(
            second_config, second_key, starttls=True)
        first_port = await first_host.start()
        second_port = await second_host.start()
        try:
            first = await asyncpg.connect(
                host='127.0.0.1', port=first_port, user=USERNAME,
                password=PASSWORD, database=DATABASE,
                ssl=_client_ssl_context(), channel_binding='require')
            await first.close()
            second = await asyncpg.connect(
                host='127.0.0.1', port=second_port, user=USERNAME,
                password=PASSWORD, database=DATABASE,
                ssl=_client_ssl_context(), channel_binding='require')
            try:
                self.assertNotEqual(
                    first_config.observed['channel_binding'],
                    second_config.observed['channel_binding'])
                self.assertTrue(second_config.observed['proof_valid'])
            finally:
                await second.close()
        finally:
            await first_host.close()
            await second_host.close()


if __name__ == '__main__':
    unittest.main()
