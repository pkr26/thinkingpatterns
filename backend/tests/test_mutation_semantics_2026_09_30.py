"""Semantic pins from the 2026-09-30 deep mutation campaign: behaviors,
not data (data-table digests live in test_mutation_pins_2026_09_30.py).

Every test here kills mutants that survived the FULL suite during the
campaign. The first class: ``app/config.py``'s environment parsing
helpers. They are the deployment's configuration contract — the
docker-compose files set these exact forms — yet nothing referenced them
directly: the whole ``_bool_env`` token sets, the fail-closed
``_secret_env`` file path, and the error prose were free to drift.
"""

from __future__ import annotations

import pytest
from starlette.middleware.cors import CORSMiddleware

from app.config import Settings, _bool_env, _float_env, _int_env, _optional_bool_env, _secret_env
from app.main import create_app


@pytest.mark.parametrize("raw", ["1", "true", "yes", "on", "TRUE", "Yes", "ON", " true "])
def test_bool_env_truthy_forms(monkeypatch, raw):
    monkeypatch.setenv("MINDPATTERN_TEST_BOOL", raw)
    assert _bool_env("MINDPATTERN_TEST_BOOL") is True
    assert _optional_bool_env("MINDPATTERN_TEST_BOOL") is True


@pytest.mark.parametrize("raw", ["0", "false", "no", "off", "FALSE", "No", "OFF", " off "])
def test_bool_env_falsy_forms(monkeypatch, raw):
    monkeypatch.setenv("MINDPATTERN_TEST_BOOL", raw)
    assert _bool_env("MINDPATTERN_TEST_BOOL") is False
    assert _optional_bool_env("MINDPATTERN_TEST_BOOL") is False


@pytest.mark.parametrize("raw", ["y", "n", "ture", "flase", "2", "-1", "on_off", "XXtrueXX"])
def test_bool_env_garbage_refuses_to_boot(monkeypatch, raw):
    """Audit item 4's fail-closed rule: a typo'd flag is a boot error,
    never a silent False (or True)."""
    monkeypatch.setenv("MINDPATTERN_TEST_BOOL", raw)
    with pytest.raises(ValueError, match=r"^environment variable MINDPATTERN_TEST_BOOL="):
        _bool_env("MINDPATTERN_TEST_BOOL")
    with pytest.raises(ValueError, match="is not a boolean$"):
        _optional_bool_env("MINDPATTERN_TEST_BOOL")


def test_bool_env_empty_means_default(monkeypatch):
    monkeypatch.delenv("MINDPATTERN_TEST_BOOL", raising=False)
    assert _bool_env("MINDPATTERN_TEST_BOOL") is False
    assert _bool_env("MINDPATTERN_TEST_BOOL", default=True) is True
    assert _optional_bool_env("MINDPATTERN_TEST_BOOL") is None
    monkeypatch.setenv("MINDPATTERN_TEST_BOOL", "   ")
    assert _bool_env("MINDPATTERN_TEST_BOOL", default=True) is True
    assert _optional_bool_env("MINDPATTERN_TEST_BOOL") is None


def test_int_env_contract(monkeypatch):
    monkeypatch.delenv("MINDPATTERN_TEST_INT", raising=False)
    assert _int_env("MINDPATTERN_TEST_INT", 7) == 7
    monkeypatch.setenv("MINDPATTERN_TEST_INT", "  42 ")
    assert _int_env("MINDPATTERN_TEST_INT", 7) == 42
    monkeypatch.setenv("MINDPATTERN_TEST_INT", "8O000")  # letter O, not zero
    with pytest.raises(ValueError, match=r"^environment variable MINDPATTERN_TEST_INT='8O000' is not an integer$"):
        _int_env("MINDPATTERN_TEST_INT", 7)
    monkeypatch.setenv("MINDPATTERN_TEST_INT", "  ")
    assert _int_env("MINDPATTERN_TEST_INT", 7) == 7


def test_float_env_contract(monkeypatch):
    monkeypatch.delenv("MINDPATTERN_TEST_FLOAT", raising=False)
    assert _float_env("MINDPATTERN_TEST_FLOAT", 1.5) == 1.5
    monkeypatch.setenv("MINDPATTERN_TEST_FLOAT", " 0.25 ")
    assert _float_env("MINDPATTERN_TEST_FLOAT", 1.5) == 0.25
    monkeypatch.setenv("MINDPATTERN_TEST_FLOAT", "fast")
    with pytest.raises(ValueError, match=r"^environment variable MINDPATTERN_TEST_FLOAT='fast' is not a number$"):
        _float_env("MINDPATTERN_TEST_FLOAT", 1.5)


def test_secret_env_env_branch_wins_and_strips(monkeypatch, tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("from-file\n")
    monkeypatch.setenv("MINDPATTERN_TEST_SECRET", "  from-env \n")
    monkeypatch.setenv("MINDPATTERN_TEST_SECRET_FILE", str(secret_file))
    assert _secret_env("MINDPATTERN_TEST_SECRET") == "from-env"


def test_secret_env_file_branch_strips_trailing_newline(monkeypatch, tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("file-secret\n\n")
    monkeypatch.delenv("MINDPATTERN_TEST_SECRET", raising=False)
    monkeypatch.setenv("MINDPATTERN_TEST_SECRET_FILE", str(secret_file))
    assert _secret_env("MINDPATTERN_TEST_SECRET", "d") == "file-secret"


def test_secret_env_empty_file_means_unset(monkeypatch, tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("   \n")
    monkeypatch.delenv("MINDPATTERN_TEST_SECRET", raising=False)
    monkeypatch.setenv("MINDPATTERN_TEST_SECRET_FILE", str(secret_file))
    assert _secret_env("MINDPATTERN_TEST_SECRET", "default-value") == "default-value"


def test_secret_env_named_file_must_be_readable(monkeypatch):
    """A half-mounted secret fails closed — never a silent default."""
    monkeypatch.delenv("MINDPATTERN_TEST_SECRET", raising=False)
    monkeypatch.setenv("MINDPATTERN_TEST_SECRET_FILE", "/nonexistent/secret.txt")
    with pytest.raises(RuntimeError, match=r"^environment variable MINDPATTERN_TEST_SECRET_FILE='/nonexistent/secret.txt' could not be read: "):
        _secret_env("MINDPATTERN_TEST_SECRET", "default-value")


def test_secret_env_unset_everywhere_means_default(monkeypatch):
    monkeypatch.delenv("MINDPATTERN_TEST_SECRET", raising=False)
    monkeypatch.delenv("MINDPATTERN_TEST_SECRET_FILE", raising=False)
    assert _secret_env("MINDPATTERN_TEST_SECRET", "the-default") == "the-default"


def _dev_app():
    s = Settings(environment="development")
    s.database_url = "sqlite+aiosqlite://"
    s.token_secret = "test-secret-not-for-production"
    return create_app(s)


def test_cors_expose_headers_contract():
    """The browser pagination contract (L-4 + the 2026-09-26 LOW-a items):
    every header the API actually sets for pagination/revision reads must
    be in the CORS expose list — exactly these, no drift. A missing entry
    silently breaks browser clients; the campaign showed the list could
    drift entry-by-entry unpunished (local variable, not a module
    constant)."""
    app = _dev_app()
    cors = [mw for mw in app.user_middleware if mw.cls is CORSMiddleware]
    assert cors, "CORS middleware must always be installed"
    assert cors[0].kwargs["expose_headers"] == [
        "X-Next-Offset",
        "X-Entries-Revision",
        "X-Notes-Revision",
        "X-Measures-Revision",
        "X-Next-Cursor",
    ]
    # native-client default: no origins allowed without an explicit allowlist
    assert cors[0].kwargs["allow_origins"] == []
