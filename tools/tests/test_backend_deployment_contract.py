"""Released deployment values and startup privacy/validation contracts.

Imports happen inside calls so a settings failure is an assertion outcome,
rather than a backend conftest collection failure.
"""

from __future__ import annotations

import dataclasses
import importlib
import json
import os
import warnings
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DEFAULTS = ROOT / "tools/tests/fixtures/deployment_defaults.json"


def _config(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    for name in list(os.environ):
        if name.startswith("MINDPATTERN_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    return importlib.import_module("app.config")


def test_released_runtime_deployment_defaults_repeat(monkeypatch):
    config = _config(monkeypatch)
    expected = json.loads(DEFAULTS.read_text())
    first = dataclasses.asdict(config.Settings(environment="development"))
    second = dataclasses.asdict(config.Settings(environment="development"))
    from_environment = dataclasses.asdict(config.Settings.from_env())
    assert first == second == from_environment == expected


def test_settings_repr_hides_every_credential_field(monkeypatch):
    config = _config(monkeypatch)
    settings = config.Settings(environment="development")
    secret_fields = (
        "database_url",
        "token_secret",
        "auth_token_secret_explicit",
        "totp_wrap_secret_explicit",
        "pairing_secret_explicit",
        "audit_mac_secret_explicit",
        "audit_mac_previous_secrets_explicit",
        "decoy_secret",
        "metrics_token",
        "llm_api_key",
        "stt_api_key",
        "audio_aws_access_key_id",
        "audio_aws_secret_access_key",
        "therapist_enrollment_token",
    )
    for name in secret_fields:
        setattr(settings, name, f"private-synthetic-value-{name}")
    rendered = repr(settings)
    for name in secret_fields:
        assert f"private-synthetic-value-{name}" not in rendered, (
            f"{name} leaked in settings repr"
        )
    assert "environment='development'" in rendered


def test_unset_environment_is_production_and_requires_separate_secrets(monkeypatch):
    config = _config(monkeypatch)
    monkeypatch.delenv("MINDPATTERN_ENV")
    values = {
        "MINDPATTERN_DB_URL": "postgresql+asyncpg://fixture:fixture@127.0.0.1/mutation",
        "MINDPATTERN_TOKEN_SECRET": "a" * 64,
        "MINDPATTERN_AUTH_TOKEN_SECRET": "b" * 64,
        "MINDPATTERN_TOTP_WRAP_SECRET": "c" * 64,
        "MINDPATTERN_PAIRING_SECRET": "d" * 64,
        "MINDPATTERN_DECOY_SECRET": "e" * 64,
        "MINDPATTERN_AUDIT_MAC_SECRET": "12" * 32,
        "MINDPATTERN_AUDIT_JOURNAL": "/synthetic/mutation-journal",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    settings = config.Settings.from_env()
    assert settings.environment == "production"
    assert (
        settings.audio_enabled is False and settings.therapist_sharing_enabled is False
    )
    assert settings.token_secret == values["MINDPATTERN_TOKEN_SECRET"]
    assert (
        settings.auth_token_secret_explicit == values["MINDPATTERN_AUTH_TOKEN_SECRET"]
    )
    assert settings.audit_journal_path == values["MINDPATTERN_AUDIT_JOURNAL"]
    # The constructor default also stays production, independently of the
    # environment reader's explicit environment keyword.
    constructor = dataclasses.asdict(settings)
    constructor.pop("environment")
    assert config.Settings(**constructor).environment == "production"
    for name in tuple(values)[1:]:
        monkeypatch.delenv(name)
        with pytest.raises(RuntimeError, match=name):
            config.Settings.from_env()
        monkeypatch.setenv(name, values[name])


def test_environment_scalars_are_strict_and_preserve_explicit_false(monkeypatch):
    config = _config(monkeypatch)
    name = "MINDPATTERN_SYNTHETIC_BOOLEAN"
    for text in ("1", "true", "yes", "on", " TRUE ", "On"):
        monkeypatch.setenv(name, text)
        assert config._bool_env(name) is True
        assert config._optional_bool_env(name) is True
    for text in ("0", "false", "no", "off", " FALSE ", "Off"):
        monkeypatch.setenv(name, text)
        assert config._bool_env(name, True) is False
        assert config._optional_bool_env(name) is False
    for text in ("", " \t"):
        monkeypatch.setenv(name, text)
        assert config._bool_env(name, True) is True
        assert config._optional_bool_env(name) is None
        assert config._int_env(name, 73) == 73
        assert config._float_env(name, 2.5) == 2.5
    for text in ("ture", "2", "-1", "enabled"):
        monkeypatch.setenv(name, text)
        with pytest.raises(ValueError, match=name):
            config._bool_env(name)
        with pytest.raises(ValueError, match=name):
            config._optional_bool_env(name)
    monkeypatch.setenv(name, " 42 ")
    assert config._int_env(name, 3) == 42
    monkeypatch.setenv(name, " 2.75 ")
    assert config._float_env(name, 3) == 2.75
    for parser in (config._int_env, config._float_env):
        monkeypatch.setenv(name, "not-a-number")
        with pytest.raises(ValueError, match=name):
            parser(name, 3)


def test_numeric_deployment_bounds_are_inclusive_and_refuse_adjacent_values(
    monkeypatch,
):
    config = _config(monkeypatch)
    bounds = {
        "token_ttl_seconds": (1, 2_592_000),
        "processing_session_ttl": (1, 300),
        "body_read_timeout_seconds": (1, 120),
        "unlock_threshold_days": (1, 3650),
        "max_entries_per_user": (1, 1_000_000),
        "max_user_blob_bytes": (1024, 8_589_934_592),
        "db_pool_timeout": (1, 600),
        "db_max_overflow": (0, None),
        "db_statement_timeout_ms": (1000, 600_000),
        "db_idle_in_transaction_timeout_ms": (1000, 3_600_000),
        "access_log_retention_days": (1, 3650),
        "audio_retention_days": (1, 3650),
        "audio_max_duration_seconds": (1, 3600),
        "audio_sweep_interval_seconds": (1, 86400),
        "audio_max_user_bytes": (1024, 8_589_934_592),
        "audio_max_body_bytes": (1024, 67_108_864),
        "body_buffer_concurrency": (1, 100_000),
        "stt_timeout_seconds": (1.0, 600.0),
    }
    for name in (
        "auth_rate_window",
        "entries_rate_window",
        "processing_rate_window",
        "read_rate_window",
        "export_rate_window",
        "ops_rate_window",
        "audio_transcribe_rate_window",
        "audio_upload_rate_window",
    ):
        bounds[name] = (1, 3600)
    for name in (
        "auth_rate_limit",
        "totp_failure_limit",
        "verifier_failure_limit",
        "entries_rate_limit",
        "processing_rate_limit",
        "read_rate_limit",
        "export_rate_limit",
        "ops_rate_limit",
        "audio_transcribe_rate_limit",
        "audio_upload_rate_limit",
    ):
        bounds[name] = (1, 100_000)
    baseline = {
        "environment": "development",
        "max_body_bytes": 1024,
        "audio_max_body_bytes": 1024,
        "analysis_blob_budget": 1024,
        "max_user_blob_bytes": 1024,
        "audio_max_user_bytes": 1024,
        "body_buffer_concurrency": 1,
    }
    for name, (lower, upper) in bounds.items():
        for value in (lower,) if upper is None else (lower, upper):
            settings = config.Settings(**{**baseline, name: value})
            assert getattr(settings, name) == value
        for value in (lower - 1,) if upper is None else (lower - 1, upper + 1):
            with pytest.raises(RuntimeError, match=name):
                config.Settings(**{**baseline, name: value})


def test_environment_overrides_reach_each_deployment_setting(monkeypatch):
    config = _config(monkeypatch)
    # Independent public environment names and intentionally nondefault
    # values: a misspelled reader must not silently use its fallback.
    settings = {
        "MINDPATTERN_TOKEN_SECRET": ("token_secret", "t" * 64),
        "MINDPATTERN_AUTH_TOKEN_SECRET": ("auth_token_secret_explicit", "a" * 64),
        "MINDPATTERN_TOTP_WRAP_SECRET": ("totp_wrap_secret_explicit", "w" * 64),
        "MINDPATTERN_PAIRING_SECRET": ("pairing_secret_explicit", "p" * 64),
        "MINDPATTERN_DECOY_SECRET": ("decoy_secret", "d" * 64),
        "MINDPATTERN_METRICS_TOKEN": ("metrics_token", "m" * 64),
        "MINDPATTERN_AUDIT_MAC_SECRET": ("audit_mac_secret_explicit", "ef" * 32),
        "MINDPATTERN_AUDIT_MAC_KEY_VERSION": ("audit_mac_key_version", 2),
        "MINDPATTERN_AUDIT_JOURNAL": (
            "audit_journal_path",
            "/synthetic/second-journal",
        ),
        "MINDPATTERN_SCRYPT_N": ("scrypt_n", 65536),
        "MINDPATTERN_TOKEN_TTL": ("token_ttl_seconds", 43200),
        "MINDPATTERN_PROCESSING_TTL": ("processing_session_ttl", 180),
        "MINDPATTERN_UNLOCK_DAYS": ("unlock_threshold_days", 45),
        "MINDPATTERN_AUTH_RATE_LIMIT": ("auth_rate_limit", 11),
        "MINDPATTERN_AUTH_RATE_WINDOW": ("auth_rate_window", 120),
        "MINDPATTERN_ENTRIES_RATE_LIMIT": ("entries_rate_limit", 150),
        "MINDPATTERN_ENTRIES_RATE_WINDOW": ("entries_rate_window", 120),
        "MINDPATTERN_PROCESSING_RATE_LIMIT": ("processing_rate_limit", 15),
        "MINDPATTERN_PROCESSING_RATE_WINDOW": ("processing_rate_window", 120),
        "MINDPATTERN_READ_RATE_LIMIT": ("read_rate_limit", 301),
        "MINDPATTERN_READ_RATE_WINDOW": ("read_rate_window", 120),
        "MINDPATTERN_BODY_READ_TIMEOUT": ("body_read_timeout_seconds", 40),
        "MINDPATTERN_MAX_BODY_BYTES": ("max_body_bytes", 3 * 1024**2),
        "MINDPATTERN_BODY_BUFFER_CONCURRENCY": ("body_buffer_concurrency", 60),
        "MINDPATTERN_MAX_ENTRIES_PER_USER": ("max_entries_per_user", 12000),
        "MINDPATTERN_MAX_USER_BLOB_BYTES": ("max_user_blob_bytes", 300 * 1024**2),
        "MINDPATTERN_RECOMPUTE_ENTRY_LIMIT": ("recompute_entry_limit", 2001),
        "MINDPATTERN_ANALYSIS_BLOB_BUDGET": ("analysis_blob_budget", 12 * 1024**2),
        "MINDPATTERN_DB_POOL_SIZE": ("db_pool_size", 7),
        "MINDPATTERN_DB_MAX_OVERFLOW": ("db_max_overflow", 11),
        "MINDPATTERN_DB_POOL_TIMEOUT": ("db_pool_timeout", 45),
        "MINDPATTERN_DB_STATEMENT_TIMEOUT_MS": ("db_statement_timeout_ms", 31000),
        "MINDPATTERN_DB_IDLE_IN_TX_TIMEOUT_MS": (
            "db_idle_in_transaction_timeout_ms",
            310000,
        ),
        "MINDPATTERN_EXPORT_RATE_LIMIT": ("export_rate_limit", 6),
        "MINDPATTERN_EXPORT_RATE_WINDOW": ("export_rate_window", 120),
        "MINDPATTERN_TOTP_FAILURE_LIMIT": ("totp_failure_limit", 11),
        "MINDPATTERN_VERIFIER_FAILURE_LIMIT": ("verifier_failure_limit", 31),
        "MINDPATTERN_OPS_RATE_LIMIT": ("ops_rate_limit", 241),
        "MINDPATTERN_OPS_RATE_WINDOW": ("ops_rate_window", 120),
        "MINDPATTERN_ACCESS_LOG_RETENTION_DAYS": ("access_log_retention_days", 731),
        "MINDPATTERN_LLM_URL": ("llm_url", "https://provider.invalid/v1/chat"),
        "MINDPATTERN_LLM_API_KEY": ("llm_api_key", "l" * 64),
        "MINDPATTERN_LLM_MODEL": ("llm_model", "synthetic-model"),
        "MINDPATTERN_LLM_PROVIDER_NAME": ("llm_provider_name", "Synthetic LLM"),
        "MINDPATTERN_LLM_DATA_RETENTION": ("llm_data_retention", "zero retention"),
        "MINDPATTERN_LLM_POLICY_VERSION": ("llm_policy_version", "v2"),
        "MINDPATTERN_AUDIO_ENABLED": ("audio_enabled", False),
        "MINDPATTERN_STT_URL": ("stt_url", "https://speech.invalid/v1"),
        "MINDPATTERN_STT_API_KEY": ("stt_api_key", "s" * 64),
        "MINDPATTERN_STT_MODEL": ("stt_model", "synthetic-speech"),
        "MINDPATTERN_STT_TIMEOUT_SECONDS": ("stt_timeout_seconds", 60.5),
        "MINDPATTERN_STT_PROVIDER_NAME": ("stt_provider_name", "Synthetic STT"),
        "MINDPATTERN_STT_DATA_RETENTION": ("stt_data_retention", "zero retention"),
        "MINDPATTERN_STT_POLICY_VERSION": ("stt_policy_version", "v2"),
        "MINDPATTERN_AUDIO_MAX_BODY_BYTES": ("audio_max_body_bytes", 5 * 1024**2),
        "MINDPATTERN_AUDIO_MAX_DURATION_SECONDS": ("audio_max_duration_seconds", 400),
        "MINDPATTERN_AUDIO_TRANSCRIBE_RATE_LIMIT": ("audio_transcribe_rate_limit", 11),
        "MINDPATTERN_AUDIO_TRANSCRIBE_RATE_WINDOW": (
            "audio_transcribe_rate_window",
            3500,
        ),
        "MINDPATTERN_AUDIO_UPLOAD_RATE_LIMIT": ("audio_upload_rate_limit", 31),
        "MINDPATTERN_AUDIO_UPLOAD_RATE_WINDOW": ("audio_upload_rate_window", 3500),
        "MINDPATTERN_AUDIO_RETENTION_DAYS": ("audio_retention_days", 40),
        "MINDPATTERN_AUDIO_LIFECYCLE_CEILING_DAYS": (
            "audio_lifecycle_ceiling_days",
            50,
        ),
        "MINDPATTERN_AUDIO_MAX_USER_BYTES": ("audio_max_user_bytes", 70 * 1024**2),
        "MINDPATTERN_AUDIO_BUCKET": ("audio_bucket", "synthetic-bucket"),
        "MINDPATTERN_AUDIO_BUCKET_REGION": ("audio_bucket_region", "us-test-1"),
        "MINDPATTERN_AUDIO_S3_ENDPOINT": (
            "audio_s3_endpoint",
            "https://objects.invalid",
        ),
        "MINDPATTERN_AWS_ACCESS_KEY_ID": ("audio_aws_access_key_id", "fixture-id"),
        "MINDPATTERN_AWS_SECRET_ACCESS_KEY": (
            "audio_aws_secret_access_key",
            "fixture-key",
        ),
        "MINDPATTERN_AUDIO_LOCAL_DIR": ("audio_local_dir", "/synthetic/audio"),
        "MINDPATTERN_AUDIO_SWEEP_INTERVAL_SECONDS": (
            "audio_sweep_interval_seconds",
            901,
        ),
        "MINDPATTERN_THERAPIST_SHARING_ENABLED": ("therapist_sharing_enabled", False),
        "MINDPATTERN_THERAPIST_ENROLLMENT_TOKEN": (
            "therapist_enrollment_token",
            "e" * 40,
        ),
        "MINDPATTERN_TRUST_PROXY_HEADERS": ("trust_proxy_headers", True),
    }
    for name, (_field, value) in settings.items():
        monkeypatch.setenv(name, str(value))
    monkeypatch.setenv(
        "MINDPATTERN_CORS_ORIGINS", " https://first.invalid , https://second.invalid, "
    )
    monkeypatch.setenv("MINDPATTERN_TRUSTED_PROXY_IPS", " 10.0.0.8, 2001:db8::8, ")
    value = config.Settings.from_env()
    for name, (field, expected) in settings.items():
        assert getattr(value, field) == expected, f"{name} did not reach {field}"
    assert value.cors_origins == ["https://first.invalid", "https://second.invalid"]
    assert value.trusted_proxy_ips == ["10.0.0.8/32", "2001:db8::8/128"]


def test_mounted_secret_resolution_and_fail_closed_read_errors(monkeypatch, tmp_path):
    config = _config(monkeypatch)
    name = "MINDPATTERN_SYNTHETIC_SECRET"
    secret = tmp_path / "mounted-secret"
    secret.write_text("  synthetic Unicode credential ሰ\n", encoding="utf-8")
    monkeypatch.setenv(name + "_FILE", str(secret))
    assert config._secret_env(name, "fallback") == "synthetic Unicode credential ሰ"
    monkeypatch.setenv(name, "  preferred environment credential\n")
    assert config._secret_env(name, "fallback") == "preferred environment credential"
    monkeypatch.setenv(name, " \n")
    secret.write_text(" \n", encoding="utf-8")
    assert config._secret_env(name, "fallback") == "fallback"
    monkeypatch.setenv(name + "_FILE", str(tmp_path / "missing"))
    with pytest.raises(RuntimeError, match=name + "_FILE"):
        config._secret_env(name, "fallback")


def test_security_boot_boundaries_and_local_provider_authorities(monkeypatch):
    config = _config(monkeypatch)
    production = {
        "environment": "production",
        "database_url": "postgresql+asyncpg://fixture/mutation",
        "token_secret": "t" * 32,
        "auth_token_secret_explicit": "a" * 32,
        "totp_wrap_secret_explicit": "w" * 32,
        "pairing_secret_explicit": "p" * 32,
        "decoy_secret": "d" * 32,
        "audit_mac_secret_explicit": "ef" * 32,
        "audit_journal_path": "/synthetic/mutation-journal",
    }
    for field in (
        "token_secret",
        "auth_token_secret_explicit",
        "totp_wrap_secret_explicit",
        "pairing_secret_explicit",
        "decoy_secret",
    ):
        assert (
            getattr(config.Settings(**{**production, field: "k" * 32}), field)
            == "k" * 32
        )
        with pytest.raises(RuntimeError):
            config.Settings(**{**production, field: "k" * 31})
    for pool, overflow in ((1, 1), (2, 0)):
        config.Settings(
            **{**production, "db_pool_size": pool, "db_max_overflow": overflow}
        )
    with pytest.raises(RuntimeError, match="db_pool_size"):
        config.Settings(**{**production, "db_pool_size": 1, "db_max_overflow": 0})
    for n in (32768, 1048576):
        assert config.Settings(environment="development", scrypt_n=n).scrypt_n == n
    for n in (32767, 32769, 1048577):
        with pytest.raises(RuntimeError, match="scrypt_n"):
            config.Settings(environment="development", scrypt_n=n)
    for key in ("a" * 63, "a" * 65, "X" * 64, "g" * 64):
        with pytest.raises(RuntimeError, match="AUDIT_MAC_SECRET"):
            config.Settings(environment="development", audit_mac_secret_explicit=key)
    for hostname in ("localhost", "127.0.0.1", "::1"):
        assert config._is_loopback_hostname(hostname)
    for hostname in (None, "localhost.evil.invalid", "127.0.0.2", "[::1]"):
        assert not config._is_loopback_hostname(hostname)
    for field in ("llm_url", "stt_url"):
        for url in ("http://localhost/v1", "http://127.0.0.1/v1", "http://[::1]/v1"):
            config.Settings(environment="development", **{field: url})
        for url in (
            "http://localhost.evil.invalid/v1",
            "https://u:p@provider.invalid/v1",
            "https://provider.invalid:bad/v1",
            "https://provider.invalid/v1?credential=x",
            "https://provider.invalid/v1#fragment",
        ):
            with pytest.raises(RuntimeError):
                config.Settings(environment="development", **{field: url})


def test_signing_properties_and_audit_rotation_keys_remain_compatible(monkeypatch):
    config = _config(monkeypatch)
    legacy = config.Settings(
        environment="development", token_secret="legacy signing material"
    )
    assert (
        legacy.auth_token_secret
        == legacy.totp_wrap_secret
        == legacy.pairing_secret
        == "legacy signing material"
    )
    assert legacy.auth_secret_version == 1
    # A released derivation vector protects existing audit rows after a reboot.
    assert (
        legacy.audit_mac_secret_hex
        == "2228f1fa976ef4f7872742336e6403924dc9963d6d11fbabad96570a5f801f07"
    )
    for field, property_name in (
        ("auth_token_secret_explicit", "auth_token_secret"),
        ("totp_wrap_secret_explicit", "totp_wrap_secret"),
        ("pairing_secret_explicit", "pairing_secret"),
    ):
        settings = config.Settings(
            environment="development", **{field: "  dedicated signing material  "}
        )
        assert getattr(settings, property_name) == "dedicated signing material"
        assert settings.auth_secret_version == (
            2 if field == "auth_token_secret_explicit" else 1
        )
        setattr(settings, field, " \n")
        assert getattr(settings, property_name) == settings.token_secret
    current, oldest, newest = "a1" * 32, "b2" * 32, "c3" * 32
    settings = config.Settings(
        environment="development",
        audit_mac_key_version=2,
        audit_mac_secret_explicit=current,
        audit_mac_previous_secrets_explicit=f"1:{oldest},2147483647:{newest}",
    )
    assert settings.audit_mac_keyring == {
        2: bytes.fromhex(current),
        1: bytes.fromhex(oldest),
        2147483647: bytes.fromhex(newest),
    }
    for version in (1, 2147483647):
        value = config.Settings(
            environment="development", audit_mac_key_version=version
        )
        assert set(value.audit_mac_keyring) == {version}
    for version in (0, 2147483648):
        with pytest.raises(RuntimeError, match="KEY_VERSION"):
            config.Settings(environment="development", audit_mac_key_version=version)
    for entry in (
        f"0:{oldest}",
        f"2147483648:{oldest}",
        f"1:{oldest[:-2]}",
        f"1:{oldest}00",
        "1:gg",
        f"2:{oldest}",
        f"1:{current}",
        f"1:{oldest}:trailing",
        f"1:{oldest},1:{newest}",
    ):
        with pytest.raises(RuntimeError):
            config.Settings(
                environment="development",
                audit_mac_key_version=2,
                audit_mac_secret_explicit=current,
                audit_mac_previous_secrets_explicit=entry,
            )


def test_proxy_allowlist_narrow_boundaries_and_operator_warnings(monkeypatch, caplog):
    config = _config(monkeypatch)
    assert config.logger.name == "mindpattern"
    for network in ("10.0.0.9/24", "2001:db8::9/64"):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            value = config.Settings(
                environment="development", trusted_proxy_ips=[network]
            )
        assert caught == []
        assert value.trusted_proxy_ips == [
            network.split("/")[0].rsplit(".", 1)[0] + ".0/24"
            if ":" not in network
            else "2001:db8::/64"
        ]
    for network, width in (("10.0.0.0/23", 24), ("2001:db8::/63", 64)):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            config.Settings(environment="development", trusted_proxy_ips=[network])
        assert len(caught) == 1 and caught[0].category is UserWarning
        assert str(caught[0].message) == (
            f"trusted_proxy_ips entry {network!r} is wider than /{width}: every host inside "
            "it can forge X-Forwarded-For identities and spend other clients' rate-limit budgets. "
            "Prefer the narrowest CIDR that actually covers the proxy tier."
        )
        assert caught[0].filename == "<string>"
    with caplog.at_level("WARNING", logger="mindpattern"):
        config.Settings(
            environment="development",
            llm_url="http://localhost/v1",
            stt_url="http://localhost/v1",
        )
    actual = [
        (record.name, record.levelname, record.getMessage())
        for record in caplog.records
    ]
    assert actual == [
        (
            "mindpattern",
            "WARNING",
            (
                "MINDPATTERN_LLM_URL is set but MINDPATTERN_LLM_API_KEY is "
                "empty — LLM requests will go out without an API key"
            ),
        ),
        (
            "mindpattern",
            "WARNING",
            (
                "MINDPATTERN_STT_URL is set but MINDPATTERN_STT_API_KEY is "
                "empty — STT requests will go out without an API key"
            ),
        ),
    ]


def test_provider_policy_lengths_and_combined_memory_capacity(monkeypatch):
    config = _config(monkeypatch)
    for prefix in ("llm", "stt"):
        for suffix, ceiling in (
            ("policy_version", 64),
            ("provider_name", 120),
            ("data_retention", 500),
        ):
            name = f"{prefix}_{suffix}"
            assert (
                getattr(
                    config.Settings(environment="development", **{name: "a" * ceiling}),
                    name,
                )
                == "a" * ceiling
            )
            with pytest.raises(RuntimeError, match=name):
                config.Settings(
                    environment="development", **{name: "a" * (ceiling + 1)}
                )
    for amount in (1024, 64 * 1024**2):
        config.Settings(
            environment="development", max_body_bytes=1024, analysis_blob_budget=amount
        )
    for amount in (1023, 64 * 1024**2 + 1):
        with pytest.raises(RuntimeError, match="analysis_blob_budget"):
            config.Settings(
                environment="development",
                max_body_bytes=1024,
                analysis_blob_budget=amount,
            )
    for amount in (1024, 67_108_864):
        config.Settings(
            environment="development",
            max_body_bytes=amount,
            analysis_blob_budget=amount,
            body_buffer_concurrency=1,
        )
    with pytest.raises(RuntimeError, match="max_body_bytes"):
        config.Settings(environment="development", max_body_bytes=67_108_865)
    for ceiling in (31, 3651):
        config.Settings(
            environment="development",
            audio_retention_days=30,
            audio_lifecycle_ceiling_days=ceiling,
        )
    for ceiling in (30, 3652):
        with pytest.raises(RuntimeError, match="audio_lifecycle_ceiling_days"):
            config.Settings(
                environment="development",
                audio_retention_days=30,
                audio_lifecycle_ceiling_days=ceiling,
            )
    config.Settings(
        environment="development",
        max_body_bytes=1024,
        analysis_blob_budget=1024,
        audio_max_body_bytes=67_108_864,
        body_buffer_concurrency=8,
    )
    with pytest.raises(RuntimeError, match="body-buffer memory budget"):
        config.Settings(
            environment="development",
            max_body_bytes=1024,
            analysis_blob_budget=1024,
            audio_max_body_bytes=67_108_864,
            body_buffer_concurrency=9,
        )


def test_released_startup_refusals_identify_each_invalid_setting(monkeypatch):
    config = _config(monkeypatch)
    # The fixture records real invalid deployments and their operator-facing
    # failures. No source text or implementation registry is inspected.
    records = json.loads(
        (ROOT / "tools/tests/fixtures/deployment_refusals.json").read_text()
    )
    for record in records:
        with pytest.raises(RuntimeError) as caught:
            config.Settings(**record["settings"])
        assert str(caught.value) == record["diagnostic"], record["name"]


def test_environment_reader_diagnostics_identify_value_and_mount(monkeypatch, tmp_path):
    config = _config(monkeypatch)
    name = "MINDPATTERN_SYNTHETIC_INPUT"
    monkeypatch.setenv(name, "not-a-number")
    with pytest.raises(ValueError) as caught:
        config._int_env(name, 1)
    assert (
        str(caught.value)
        == f"environment variable {name}='not-a-number' is not an integer"
    )
    monkeypatch.setenv(name, "invalid-toggle")
    for function in (config._bool_env, config._optional_bool_env):
        with pytest.raises(ValueError) as caught:
            function(name)
        assert (
            str(caught.value)
            == f"environment variable {name}='invalid-toggle' is not a boolean"
        )
    monkeypatch.delenv(name)
    missing = tmp_path / "missing-mounted-credential"
    monkeypatch.setenv(name + "_FILE", str(missing))
    with pytest.raises(RuntimeError) as caught:
        config._secret_env(name)
    original = caught.value.__cause__
    assert isinstance(original, FileNotFoundError)
    assert str(caught.value) == (
        f"environment variable {name}_FILE={str(missing)!r} could not be read: {original}"
    )


def test_final_authority_credentials_and_rotation_environment_boundaries(monkeypatch):
    config = _config(monkeypatch)
    production = {
        "environment": "production",
        "database_url": "postgresql+asyncpg://fixture/mutation",
        "token_secret": "t" * 32,
        "auth_token_secret_explicit": "a" * 32,
        "totp_wrap_secret_explicit": "w" * 32,
        "pairing_secret_explicit": "p" * 32,
        "decoy_secret": "d" * 32,
        "audit_mac_secret_explicit": "ef" * 32,
        "audit_journal_path": "/synthetic/mutation-journal",
    }
    for origin in ("http://localhost", "http://127.0.0.1", "http://[::1]"):
        config.Settings(environment="development", cors_origins=[origin])
    with pytest.raises(RuntimeError, match="cors_origins"):
        config.Settings(environment="development", cors_origins=["https://"])
    for field in ("llm_url", "stt_url"):
        with pytest.raises(RuntimeError):
            config.Settings(environment="development", **{field: "https:///v1"})
    for amount in (32, 64):
        config.Settings(**{**production, "metrics_token": "m" * amount})
    with pytest.raises(RuntimeError, match="METRICS_TOKEN"):
        config.Settings(**{**production, "metrics_token": "m" * 31})
    for n in (32, 16384, 2097152):
        with pytest.raises(RuntimeError, match="scrypt_n"):
            config.Settings(environment="development", scrypt_n=n)
    config.Settings(environment="development", db_pool_size=1, db_max_overflow=0)
    for prefix in ("llm", "stt"):
        provider = {
            f"{prefix}_url": "https://provider.invalid/v1",
            f"{prefix}_provider_name": "Synthetic provider",
            f"{prefix}_data_retention": "zero retention",
            f"{prefix}_policy_version": "v1",
        }
        config.Settings(**{**production, **provider})
        for suffix, environment_name in (
            ("provider_name", "PROVIDER_NAME"),
            ("data_retention", "DATA_RETENTION"),
            ("policy_version", "POLICY_VERSION"),
        ):
            with pytest.raises(RuntimeError) as caught:
                config.Settings(**{**production, **provider, f"{prefix}_{suffix}": ""})
            expected_prefix = (
                "an enabled production LLM requires explicit provider, retention, and policy "
                "version declarations"
                if prefix == "llm"
                else "a configured production STT requires explicit provider, retention, and policy version declarations"
            )
            assert (
                str(caught.value)
                == f"{expected_prefix} (set MINDPATTERN_{prefix.upper()}_{environment_name})"
            )
    config.Settings(
        **{
            **production,
            "therapist_sharing_enabled": True,
            "therapist_enrollment_token": "e" * 32,
        }
    )
    with pytest.raises(RuntimeError, match="THERAPIST_ENROLLMENT_TOKEN"):
        config.Settings(
            **{
                **production,
                "therapist_sharing_enabled": True,
                "therapist_enrollment_token": "e" * 31,
            }
        )
    monkeypatch.setenv("MINDPATTERN_AUDIT_MAC_KEY_VERSION", "2")
    monkeypatch.setenv("MINDPATTERN_AUDIT_MAC_SECRET", "ef" * 32)
    monkeypatch.setenv("MINDPATTERN_AUDIT_MAC_PREVIOUS_SECRETS", "1:" + "ab" * 32)
    assert config.Settings.from_env().audit_mac_keyring == {
        2: bytes.fromhex("ef" * 32),
        1: bytes.fromhex("ab" * 32),
    }


def test_defensive_keyring_and_minimum_refusals_keep_named_diagnostics(monkeypatch):
    config = _config(monkeypatch)
    # Public settings remain mutable: key consumers must give a useful named
    # refusal if a runtime swap supplies malformed key material.
    settings = config.Settings(environment="development")
    for value in ("g" * 64, "ef"):
        settings.audit_mac_secret_explicit = value
        with pytest.raises(RuntimeError) as caught:
            _ = settings.audit_mac_keyring
        assert (
            str(caught.value)
            == "MINDPATTERN_AUDIT_MAC_SECRET must be 32 bytes of hex (64 chars)"
        )
    with pytest.raises(RuntimeError) as caught:
        config.Settings(environment="development", token_ttl_seconds=0)
    assert str(caught.value) == "token_ttl_seconds must be >= 1"
    with pytest.raises(RuntimeError) as caught:
        config.Settings(environment="development", decoy_secret="short")
    assert (
        str(caught.value) == "MINDPATTERN_DECOY_SECRET must be at least 32 characters"
    )
