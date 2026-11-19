"""Authenticator-app codes worked out the way the apps do it (RFC 6238: HMAC-SHA1 of
the 30-second time step, 6 digits), independently of allauth's own code, so the tests
prove the setup works with a real app."""

import base64
import hashlib
import hmac
import struct
import time

STEP_SECONDS = 30
DIGITS = 6


def code(secret, at=None):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    counter = int((time.time() if at is None else at) // STEP_SECONDS)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)
