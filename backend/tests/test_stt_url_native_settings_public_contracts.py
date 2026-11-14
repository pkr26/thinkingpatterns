"""Actual Settings accepts secure STT URLs and the documented local exception."""

import pytest

from app.config import Settings


@pytest.mark.parametrize(
    "url",
    [
        "https://speech.example.test",
        "http://127.0.0.1:7860",
    ],
)
def test_native_settings_accepts_supported_stt_authorities(url):
    settings = Settings(
        environment="development",
        stt_url=url,
        stt_api_key="owned-settings-validation-key",
    )
    assert settings.stt_url == url
