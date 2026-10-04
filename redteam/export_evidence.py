"""Pure checks for the ciphertext export's recovery and privacy contract."""

from __future__ import annotations

import base64
import json


def inspect_export(
    bundle: object, expected: dict, secrets: dict[str, str | bytes]
) -> list[str]:
    """Required public recovery metadata is allowed; secret material is not."""
    if not isinstance(bundle, dict):
        return ["export is not an object"]
    issues = []
    for key, value in expected.items():
        if bundle.get(key) != value:
            issues.append(f"missing/incorrect recovery field: {key}")
    if not isinstance(bundle.get("entries"), list) or not bundle["entries"]:
        issues.append("expected encrypted entry is missing")
    rendered = json.dumps(bundle, ensure_ascii=True, sort_keys=True)
    for label, secret in secrets.items():
        encodings = (
            # Match JSON's representation, including escaped punctuation,
            # line breaks and non-ASCII text in real journal/password values.
            [json.dumps(secret, ensure_ascii=True)[1:-1]]
            if isinstance(secret, str)
            else [
                base64.b64encode(secret).decode("ascii"),
                secret.hex(),
                json.dumps(list(secret)),
            ]
        )
        if any(value and value in rendered for value in encodings):
            issues.append(f"plaintext secret present: {label}")
    forbidden = {"text", "plaintext", "password", "verifier", "auth_key", "data_key"}

    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in forbidden:
                    issues.append(f"plaintext secret field present: {key}")
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(bundle)
    return issues
