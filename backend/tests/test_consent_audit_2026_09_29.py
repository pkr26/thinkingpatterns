"""Consent toggles write audit-trail rows (deep audit 2026-09-29, MEDIUM).

The LLM and voice consent toggles mutated ``users.llm_consent*`` /
``voice_consent*`` and committed with NO ``append_access_log`` row —
the system's most consequential privacy decision (journal text/audio
flowing to a third-party processor) was invisible to the hash-chained,
MAC-sealed trail that records every therapist read. Worse, the consent
columns are silently REWRITTEN on every toggle, so a disputed
withdrawal retained no evidence at all (GDPR Art. 7/Art. 30 gap).
"""

from __future__ import annotations

import pytest

from tests.helpers import ClientEmulator
from tests.test_voice_remediation_2026_09_29 import _grant_llm_consent


async def _register(client, settings, name: str) -> ClientEmulator:
    settings.audio_enabled = True
    settings.stt_url = "https://stt.example.com/v1"
    settings.stt_api_key = "k"
    settings.llm_url = "https://llm.example.com/v1"
    settings.llm_api_key = "k"
    emu = ClientEmulator(name, "correct horse battery staple")
    await emu.register(client)
    return emu


async def _actions(client, emu) -> list[str]:
    response = await client.get("/api/account/access-log", headers=emu.headers)
    assert response.status_code == 200, response.text
    return [row["action"] for row in response.json()]


@pytest.mark.asyncio
class TestConsentTogglesAreAudited:
    async def test_voice_consent_toggle_writes_on_and_off_rows(
        self, client, settings
    ):
        emu = await _register(client, settings, "consent-audit-v")
        on = await client.put(
            "/api/account/voice-consent",
            headers=emu.headers,
            json={"enabled": True, "verifier": emu.auth_key_b64},
        )
        assert on.status_code == 200, on.text
        off = await client.put(
            "/api/account/voice-consent",
            headers=emu.headers,
            json={"enabled": False, "verifier": emu.auth_key_b64},
        )
        assert off.status_code == 200, off.text
        actions = await _actions(client, emu)
        assert "voice_consent_on" in actions
        assert "voice_consent_off" in actions

    async def test_llm_consent_toggle_writes_on_and_off_rows(
        self, client, settings
    ):
        emu = await _register(client, settings, "consent-audit-l")
        await _grant_llm_consent(client, emu)
        off = await client.put(
            "/api/account/llm-consent",
            headers=emu.headers,
            json={"enabled": False, "verifier": emu.auth_key_b64},
        )
        assert off.status_code == 200, off.text
        actions = await _actions(client, emu)
        assert "llm_consent_on" in actions
        assert "llm_consent_off" in actions

    async def test_rows_are_patient_visible_and_attributed_to_self(
        self, client, settings
    ):
        """The rows land in the patient's own WHO-ACCESSED-MY-DATA view,
        attributed to "self" — visible evidence, not a hidden column."""
        emu = await _register(client, settings, "consent-audit-c")
        on = await client.put(
            "/api/account/voice-consent",
            headers=emu.headers,
            json={"enabled": True, "verifier": emu.auth_key_b64},
        )
        assert on.status_code == 200, on.text
        response = await client.get("/api/account/access-log", headers=emu.headers)
        rows = response.json()
        consent_rows = [r for r in rows if r["action"].startswith("voice_consent_")]
        assert len(consent_rows) == 1
        assert consent_rows[0]["actor"] == "self"
