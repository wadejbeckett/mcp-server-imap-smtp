# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest
from mcp_server_imap_smtp import crypto

def test_seal_roundtrip_and_tamper():
    k = crypto.new_key()
    blob = crypto.seal(k, b"hunter2", b"grant1|a@b.co")
    assert crypto.unseal(k, blob, b"grant1|a@b.co") == b"hunter2"
    with pytest.raises(crypto.CryptoError):
        crypto.unseal(k, blob, b"grant2|a@b.co")          # wrong AAD
    with pytest.raises(crypto.CryptoError):
        crypto.unseal(crypto.new_key(), blob, b"grant1|a@b.co")

def test_wrap_needs_the_token_secret():
    k = crypto.new_key(); s = crypto.new_secret()
    w = crypto.wrap_key(k, s, "access:t1")
    assert crypto.unwrap_key(w, s, "access:t1") == k
    with pytest.raises(crypto.CryptoError):
        crypto.unwrap_key(w, crypto.new_secret(), "access:t1")
    with pytest.raises(crypto.CryptoError):
        crypto.unwrap_key(w, s, "refresh:t1")

def test_token_format():
    t = crypto.make_token("at", "abc", "s3cr3t")
    assert crypto.split_token(t) == ("at", "abc", "s3cr3t")
    assert crypto.split_token("garbage") is None
    assert crypto.split_token("at_abc") is None
    assert crypto.hash_secret("x") != crypto.hash_secret("y")
