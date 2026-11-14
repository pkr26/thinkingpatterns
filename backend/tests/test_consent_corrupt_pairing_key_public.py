"""Malformed stored clinician keys must not escape through pairing lookup."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import update

from app.models import User
from tests.helpers import ClientEmulator, TherapistEmulator


@pytest.mark.parametrize(
    "damage", ["invalid_base64", "invalid_der", "wrong_curve", "unknown_algorithm", "unknown_curve"]
)
async def test_pairing_lookup_refuses_corrupt_public_key_without_consuming_code(
    client, app, damage
):
    patient = ClientEmulator("corrupt-key-patient", "test-password")
    clinician = TherapistEmulator("corrupt-key-clinician", "test-password")
    await patient.register(client)
    await clinician.register(client)
    code = await clinician.create_pairing_code(client)

    # A legacy or damaged database can contain invalid base64 or a decoded
    # value that is not a usable public key. Neither may reach the patient.
    if damage == "invalid_base64":
        corrupt_key = clinician.wrap_pub_key + "!"
    elif damage == "invalid_der":
        corrupt_key = base64.b64encode(b"not a public key").decode("ascii")
    elif damage in ("unknown_algorithm", "unknown_curve"):
        der = bytearray(base64.b64decode(clinician.wrap_pub_key, validate=True))
        # Change an OID component while preserving the DER structure.
        offset = 12 if damage == "unknown_algorithm" else 22
        assert der[offset] == (1 if damage == "unknown_algorithm" else 7)
        der[offset] ^= 1 if damage == "unknown_algorithm" else 0x7F
        corrupt_key = base64.b64encode(der).decode("ascii")
    else:
        der = (
            ec.generate_private_key(ec.SECP384R1())
            .public_key()
            .public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        corrupt_key = base64.b64encode(der).decode("ascii")
    async with app.state.sessionmaker() as session:
        await session.execute(
            update(User).where(User.id == clinician.user_id).values(wrap_pub_key=corrupt_key)
        )
        await session.commit()

    refused = await patient.pairing_lookup(client, code)
    assert refused == {
        "status": 404,
        "body": {"detail": "pairing code not found", "code": "not_found"},
    }

    async with app.state.sessionmaker() as session:
        await session.execute(
            update(User)
            .where(User.id == clinician.user_id)
            .values(wrap_pub_key=clinician.wrap_pub_key)
        )
        await session.commit()

    repaired = await patient.pairing_lookup(client, code)
    assert repaired["status"] == 200, repaired
    assert repaired["body"]["wrap_pub_key"] == clinician.wrap_pub_key
    assert repaired["body"]["therapist_id"] == clinician.user_id
