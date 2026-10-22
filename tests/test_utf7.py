# SPDX-License-Identifier: AGPL-3.0-or-later
from mcp_server_imap_smtp.mail import utf7

def test_ascii_passthrough():
    assert utf7.encode("INBOX.Sent") == "INBOX.Sent" and utf7.decode("INBOX.Sent") == "INBOX.Sent"

def test_ampersand():
    assert utf7.encode("R&D") == "R&-D" and utf7.decode("R&-D") == "R&D"

def test_nonascii_roundtrip():
    for name in ("INBOX.Afrikaans ê", "Entwürfe", "日本語", "Kopie & Archief ✓"):
        assert utf7.decode(utf7.encode(name)) == name
    assert utf7.encode("Entwürfe") == "Entw&APw-rfe"   # RFC 3501 example form

def test_malformed_utf7():
    # Test ampersand with no closing dash
    assert utf7.decode("Folder&NAME") == "Folder&NAME"
    # Test invalid base64
    assert utf7.decode("Folder&!!!-NAME") == "Folder&!!!-NAME"

def test_malformed_utf7_whole_input():
    # Test that entire raw input is returned unchanged on any malformed segment
    assert utf7.decode("&!&AOo-x") == "&!&AOo-x"
    assert utf7.decode("A&B&APw-") == "A&B&APw-"
    assert utf7.decode("&AOo-&bad") == "&AOo-&bad"
    # Valid names still decode
    assert utf7.decode("&AOo-") == "ê"
