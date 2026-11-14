"""Backend reference contracts open actual portal WebCrypto payloads."""

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.security import crypto, sharing
from app.security.kdf import hkdf_sha256

VECTOR = json.loads(
    (Path(__file__).parent / "fixtures" / "portal_reference_security_vectors.json").read_text()
)


def test_exported_reference_schedule_and_contexts_interoperate_with_actual_portal_crypto():
    master = bytes.fromhex(VECTOR["masterHex"])
    wrap_kek = hkdf_sha256(master, None, sharing.PORTAL_WRAP_INFO)
    note_key = hkdf_sha256(master, None, sharing.PORTAL_NOTES_INFO)
    assert wrap_kek.hex() == VECTOR["portalDerivedKeys"]["wrapKekHex"]
    assert note_key.hex() == VECTOR["portalDerivedKeys"]["noteKeyHex"]

    public_der = base64.b64decode(VECTOR["keyPair"]["publicKeySpkiB64"])
    assert sharing.SPKI_P256_DER_BYTES == len(public_der)
    private_der = crypto.decrypt(
        wrap_kek,
        base64.b64decode(VECTOR["keyPair"]["wrapKeyBlobB64"]),
        crypto.build_aad(sharing.THERAPIST_KEY_CONTEXT, VECTOR["username"]),
    )
    private_key = sharing.load_private_key_pkcs8(private_der)
    assert private_key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    ) == (public_der)
    payload = crypto.decrypt(
        note_key,
        base64.b64decode(VECTOR["note"]["blobB64"]),
        crypto.build_aad(
            sharing.NOTE_CONTEXT,
            VECTOR["therapistId"],
            VECTOR["patientId"],
            VECTOR["clientNoteId"],
        ),
    )
    assert json.loads(payload) == {"v": 1, "text": VECTOR["text"]}
