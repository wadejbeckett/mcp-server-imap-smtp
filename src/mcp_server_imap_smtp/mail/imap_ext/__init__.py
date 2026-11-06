# SPDX-License-Identifier: AGPL-3.0-or-later
"""One mixin per family of IMAP extensions; ImapClient in imap.py inherits them all. A mixin imports only
from imap_wire and imap_types, never from imap, so there is no import cycle."""
