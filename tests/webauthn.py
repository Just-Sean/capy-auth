"""A software passkey, standing in for a phone or security key, so the tests prove a
real passkey works with the server: it makes the browser's answers to allauth's
WebAuthn requests the way an authenticator does (a "none" attestation, ES256
signatures), using fido2 and cryptography, which come with allauth's MFA."""

import json
import os
import re

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ES256
from fido2.utils import sha256, websafe_decode, websafe_encode
from fido2.webauthn import (
    Aaguid,
    AttestationObject,
    AttestedCredentialData,
    AuthenticatorData,
    CollectedClientData,
)

ORIGIN = "https://testserver"  # the browser's origin: allauth checks it's https
FLAG = AuthenticatorData.FLAG


def page_data(page):
    """The options allauth puts on a page for its script (json_script id="js_data")."""
    match = re.search(r'<script id="js_data" type="application/json">(.*?)</script>', page, re.S)
    return json.loads(match.group(1))


class SoftPasskey:
    def __init__(self, passkey=True):
        self.passkey = passkey  # signs in on its own (a "resident" key) or a second step
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(16)
        self.user_handle = None
        self.counter = 0
        self.verifies_user = True  # asks for a fingerprint, face or PIN (the UV flag)
        self.origin = ORIGIN  # the site the browser says it's on

    def register(self, creation_options):
        options = creation_options["publicKey"]
        self.user_handle = options["user"]["id"]
        client_data = CollectedClientData.create(
            CollectedClientData.TYPE.CREATE, websafe_decode(options["challenge"]), self.origin
        )
        public_key = ES256.from_cryptography_key(self.key.public_key())
        credential = AttestedCredentialData.create(Aaguid.NONE, self.credential_id, public_key)
        auth_data = AuthenticatorData.create(
            sha256(options["rp"]["id"].encode()),
            self.flags() | FLAG.AT,
            self.counter,
            credential,
        )
        attestation = AttestationObject.create("none", auth_data, {})
        return self.answer(
            {
                "clientDataJSON": websafe_encode(bytes(client_data)),
                "attestationObject": websafe_encode(bytes(attestation)),
            },
            {"credProps": {"rk": self.passkey}},
        )

    def sign(self, request_options):
        options = request_options["publicKey"]
        self.counter += 1
        client_data = CollectedClientData.create(
            CollectedClientData.TYPE.GET, websafe_decode(options["challenge"]), self.origin
        )
        auth_data = AuthenticatorData.create(
            sha256(options["rpId"].encode()), self.flags(), self.counter
        )
        signature = self.key.sign(
            bytes(auth_data) + sha256(bytes(client_data)), ec.ECDSA(hashes.SHA256())
        )
        response = {
            "clientDataJSON": websafe_encode(bytes(client_data)),
            "authenticatorData": websafe_encode(bytes(auth_data)),
            "signature": websafe_encode(signature),
        }
        if self.passkey:
            response["userHandle"] = self.user_handle
        return self.answer(response, {})

    def flags(self):
        return FLAG.UP | FLAG.UV if self.verifies_user else FLAG.UP

    def answer(self, response, extensions):
        credential_id = websafe_encode(self.credential_id)
        return json.dumps(
            {
                "id": credential_id,
                "rawId": credential_id,
                "type": "public-key",
                "response": response,
                "clientExtensionResults": extensions,
            }
        )
