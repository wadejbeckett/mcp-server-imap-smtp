# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-grant credential sealing. The server stores ciphertext and secret hashes; the
key that opens a grant's mailbox passwords is recoverable only with a live token."""
from __future__ import annotations

import hashlib
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


class CryptoError(Exception):
    pass


def new_key() -> bytes:
    return os.urandom(32)


def new_secret() -> str:
    return secrets.token_urlsafe(32)


def make_token(prefix: str, ident: str, secret: str) -> str:
    return f"{prefix}_{ident}.{secret}"


def split_token(token: str) -> tuple[str, str, str] | None:
    head, dot, secret = token.partition(".")
    prefix, us, ident = head.partition("_")
    if not (dot and us and prefix and ident and secret):
        return None
    return prefix, ident, secret


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def unseal(key: bytes, blob: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(blob[:12], blob[12:], aad)
    except (InvalidTag, ValueError) as exc:
        raise CryptoError("cannot open sealed value") from exc


def _kek(secret: str, context: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context.encode()).derive(secret.encode())


def wrap_key(key: bytes, secret: str, context: str) -> bytes:
    return seal(_kek(secret, context), key, context.encode())


def unwrap_key(blob: bytes, secret: str, context: str) -> bytes:
    return unseal(_kek(secret, context), blob, context.encode())


# Sealing to a grant's public key: a mailbox added from the manage page (where no token, so no grant key,
# is at hand) is sealed so that only the grant key, through the grant's private key, can open it.
def new_keypair() -> tuple[bytes, bytes]:
    """(public, private) raw X25519 keys."""
    private = X25519PrivateKey.generate()
    return (private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))


def public_of(private: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _box_key(shared: bytes, ephemeral: bytes, public: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=ephemeral + public,
                info=b"hosted-mcp sealed box").derive(shared)   # a fixed protocol label: changing it breaks sealed rows


def seal_to(public: bytes, plaintext: bytes, aad: bytes) -> bytes:
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key = _box_key(eph.exchange(X25519PublicKey.from_public_bytes(public)), eph_pub, public)
    return eph_pub + seal(key, plaintext, aad)


def open_sealed(private: bytes, blob: bytes, aad: bytes) -> bytes:
    try:
        priv = X25519PrivateKey.from_private_bytes(private)
        eph_pub = blob[:32]
        public = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        key = _box_key(priv.exchange(X25519PublicKey.from_public_bytes(eph_pub)), eph_pub, public)
    except ValueError as exc:
        raise CryptoError("cannot open sealed value") from exc
    return unseal(key, blob[32:], aad)
