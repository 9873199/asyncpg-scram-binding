# Copyright (C) 2016-present the asyncpg authors and contributors
# <see AUTHORS file>
#
# This module is part of asyncpg and is released under
# the Apache 2.0 License: http://www.apache.org/licenses/LICENSE-2.0


"""SCRAM channel binding negotiation and tls-server-end-point support.

This module implements the parts of SCRAM-SHA-256-PLUS channel binding that
must be shared between the pure-Python connection layer (parameter parsing,
TLS transport inspection) and the Cython authentication state machine:

* :class:`ChannelBindingMode` parses and validates the ``channel_binding``
  connection parameter (``disable`` / ``prefer`` / ``require``);
* :func:`get_tls_server_end_point` computes the ``tls-server-end-point``
  channel binding data from the negotiated TLS channel, following RFC 5929
  and the weak-hash fallback rules of RFC 5929 section 4.1;
* :func:`build_channel_binding_header` renders the GS2 channel-binding
  header (RFC 5802 section 6 / RFC 5801 section 4) that both the SCRAM
  ``p=`` proof and the ``c=`` attribute are bound to.

Channel binding is only ever computed from the TLS transport of the
connection that is authenticating, so a proof can never be replayed over a
different TLS channel.
"""

from __future__ import annotations

import enum
import hashlib
import typing

from .exceptions._base import ClientConfigurationError, InterfaceError


# The only channel binding type PostgreSQL advertises for
# SCRAM-SHA-256-PLUS.
TLS_SERVER_END_POINT = b'tls-server-end-point'

# RFC 5929 section 4.1: these digest algorithms are considered weak, so the
# end-point hash is computed with SHA-256 instead of the certificate's own
# signature hash.
_WEAK_CERTIFICATE_DIGESTS = frozenset({'md5', 'sha1'})


class ChannelBindingMode(enum.Enum):
    """The three values of the ``channel_binding`` connection parameter."""

    disable = 'disable'
    prefer = 'prefer'
    require = 'require'

    @classmethod
    def parse(cls, value: typing.Union['ChannelBindingMode', str, None]
              ) -> 'ChannelBindingMode':
        if value is None:
            return cls.disable
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            raise ClientConfigurationError(
                '`channel_binding` parameter must be one of: {}'.format(
                    ', '.join(m.value for m in cls)
                )
            )
        try:
            return cls(value)
        except ValueError:
            raise ClientConfigurationError(
                '`channel_binding` parameter must be one of: {}, '
                'got {!r}'.format(
                    ', '.join(m.value for m in cls), value
                )
            ) from None


def _leaf_to_der(certificate: typing.Union[bytes, typing.Any]) -> bytes:
    # Python 3.14+ returns chain entries as raw DER bytes; older versions
    # return cryptography x509.Certificate objects.
    if isinstance(certificate, (bytes, bytearray, memoryview)):
        return bytes(certificate)
    return certificate.public_bytes(_x509_encoding_der())


def _get_peer_certificate_der(
        ssl_object: typing.Any) -> typing.Optional[bytes]:
    """Return the DER-encoded leaf certificate of the TLS peer.

    The unverified chain is preferred because channel binding must describe
    the certificate actually presented on this channel even when the client
    does not verify it (e.g. ``sslmode=require``).  Returns ``None`` when the
    transport carries no peer certificate.
    """
    get_chain = getattr(ssl_object, 'get_unverified_chain', None)
    if get_chain is not None:
        chain = get_chain()
        if chain:
            return _leaf_to_der(chain[0])

    # Fallback for Python builds without get_unverified_chain(): when the
    # certificate was verified, the verified chain contains it; the binary
    # form is only populated for binary-form getpeercert() calls.
    get_verified_chain = getattr(ssl_object, 'get_verified_chain', None)
    if get_verified_chain is not None:
        chain = get_verified_chain()
        if chain:
            return _leaf_to_der(chain[0])

    der_cert = ssl_object.getpeercert(binary_form=True)
    if der_cert:
        return der_cert
    return None


def _x509_encoding_der():
    # Imported lazily so that merely importing asyncpg does not require the
    # cryptography package (it is part of the standard library ssl module's
    # certificate representation, but only needed for channel binding).
    from cryptography.hazmat.primitives import serialization
    return serialization.Encoding.DER


def _get_certificate_signature_hash(der_cert: bytes) -> str:
    """Return the name of the hash used in the leaf certificate's signature."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    certificate = x509.load_der_x509_certificate(der_cert)
    hash_algorithm = certificate.signature_hash_algorithm
    if hash_algorithm is None:
        # Ed25519/Ed448 (and other "pure" signature algorithms) have no
        # separate hash; RFC 5929's fallback rule does not name them, so use
        # SHA-256 as the tls-server-end-point digest.
        return 'sha256'
    if not isinstance(hash_algorithm, hashes.HashAlgorithm):
        raise InterfaceError(
            'cannot determine the signature hash algorithm of the TLS '
            'server certificate for tls-server-end-point channel binding')
    return hash_algorithm.name.lower()


def get_tls_server_end_point(ssl_object: typing.Any) -> bytes:
    """Compute the tls-server-end-point channel binding data.

    Implements RFC 5929 section 4.1: the SHA-256 hash of the DER-encoded
    peer (leaf) certificate, except that when the certificate is signed
    using MD5 or SHA-1, the client must hash with SHA-256 anyway.  A peer
    whose signature algorithm is not supported by the available crypto
    backends raises :class:`~asyncpg.exceptions.InterfaceError` instead of
    silently producing an unbindable connection.
    """
    if ssl_object is None:
        raise InterfaceError(
            'tls-server-end-point channel binding requires a TLS '
            'connection, but the transport is not TLS')

    der_cert = _get_peer_certificate_der(ssl_object)
    if not der_cert:
        raise InterfaceError(
            'could not obtain the TLS server certificate for '
            'tls-server-end-point channel binding')

    try:
        signature_hash = _get_certificate_signature_hash(der_cert)
    except Exception as ex:
        raise InterfaceError(
            'unsupported TLS server certificate signature algorithm; '
            'cannot compute tls-server-end-point channel binding: '
            '{}'.format(ex)) from ex

    if signature_hash in _WEAK_CERTIFICATE_DIGESTS:
        digest_name = 'sha256'
    else:
        digest_name = signature_hash

    try:
        digest = hashlib.new(digest_name)
    except (ValueError, TypeError) as ex:
        raise InterfaceError(
            'unsupported TLS server certificate signature hash {!r}; '
            'cannot compute tls-server-end-point channel binding'.format(
                signature_hash)) from ex

    digest.update(der_cert)
    return digest.digest()


def get_channel_binding_data(ssl_object: typing.Any) -> bytes:
    """Return the tls-server-end-point binding bytes of a TLS transport."""
    return get_tls_server_end_point(ssl_object)


def build_channel_binding_header(
        binding_data: typing.Optional[bytes]) -> bytes:
    """Build the GS2 channel-binding header for a SCRAM exchange.

    With binding data (SCRAM-SHA-256-PLUS) the header is
    ``p=tls-server-end-point,,``; without it (plain SCRAM-SHA-256) it is the
    RFC 5801 downgrade-safe header ``n,,``.
    """
    if binding_data is None:
        return b'n,,'
    return b'p=' + TLS_SERVER_END_POINT + b',,'


def get_scram_mechanisms(
    advertised_mechanisms: typing.List[bytes],
    mode: ChannelBindingMode,
    ssl_object: typing.Any,
) -> typing.Tuple[typing.Optional[bytes], typing.Optional[bytes], bool]:
    """Choose a SASL mechanism and prepare the channel binding for it.

    Returns a ``(mechanism, binding_data, plus_selected)`` tuple where
    ``binding_data`` is ``None`` for plain SCRAM-SHA-256 and the
    tls-server-end-point bytes for SCRAM-SHA-256-PLUS.

    ``require`` never downgrades: a non-TLS transport, missing binding data,
    or a server that does not advertise SCRAM-SHA-256-PLUS all fail.
    ``prefer`` selects PLUS whenever both the transport and the server
    support it, and otherwise falls back to plain SCRAM with the GS2 ``n,,``
    header (the explicit RFC 5801 signal that channel binding was not used).
    """
    plus_supported = b'SCRAM-SHA-256-PLUS' in advertised_mechanisms
    plain_supported = b'SCRAM-SHA-256' in advertised_mechanisms

    if mode is ChannelBindingMode.disable:
        if plain_supported:
            return b'SCRAM-SHA-256', None, False
        # Keep the old behavior: let the caller report the server's
        # unsupported mechanisms rather than failing here.
        return None, None, False

    if mode is ChannelBindingMode.require:
        if ssl_object is None:
            raise InterfaceError(
                'channel_binding=require requires a TLS connection, but '
                'the connection is not using TLS')
        if not plus_supported:
            raise InterfaceError(
                'channel_binding=require requires the server to support '
                'SCRAM-SHA-256-PLUS, but the server only advertised: {!r}'
                .format([m.decode('ascii', 'replace')
                         for m in advertised_mechanisms]))
        binding_data = get_channel_binding_data(ssl_object)
        return b'SCRAM-SHA-256-PLUS', binding_data, True

    # mode is ChannelBindingMode.prefer
    if plus_supported:
        if ssl_object is None:
            # No TLS channel to bind: correct GS2 downgrade to plain SCRAM.
            if plain_supported:
                return b'SCRAM-SHA-256', None, False
            return None, None, False
        try:
            binding_data = get_channel_binding_data(ssl_object)
        except InterfaceError:
            # The binding data cannot be computed on this channel: the only
            # safe negotiated fallback is plain SCRAM with its GS2 signal.
            if not plain_supported:
                raise
            return b'SCRAM-SHA-256', None, False
        return b'SCRAM-SHA-256-PLUS', binding_data, True

    if plain_supported:
        return b'SCRAM-SHA-256', None, False
    return None, None, False
