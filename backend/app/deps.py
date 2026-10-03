"""Shared FastAPI dependencies and the error-envelope contract.

Every error response the API emits (endpoint-raised or default) is::

    {"detail": <human string, never echoing input>, "code": <machine string>}

Endpoints raise :class:`ApiError` with an explicit code; the exception
handler in main.py renders the envelope, falling back to the per-status
defaults below for exceptions raised by the framework itself (404 on
unknown routes, 405, ...). Mobile clients branch on ``code`` and display
``detail`` — both must stay stable, and ``detail`` must stay a STRING
(never the old FastAPI list-of-objects validation shape).
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import ROLE_THERAPIST, ROLE_USER, RekeyJournal, User
from .security import tokens

# Codes assigned when the raised exception carries no explicit one.
DEFAULT_ERROR_CODES: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    408: "request_timeout",
    409: "conflict",
    410: "gone",
    413: "payload_too_large",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
    503: "service_unavailable",
}


class ApiError(HTTPException):
    """HTTPException carrying the machine-readable `code` of the envelope."""

    def __init__(
        self, status_code: int, detail: str, code: str, headers: dict | None = None
    ) -> None:
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.code = code


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    from sqlalchemy import event

    from .api._audit import flush_audit_journal

    async with request.app.state.sessionmaker() as session:
        # Independent audit 2026-09-27: the audit journal must be appended
        # strictly AFTER the handler's commit (a pre-commit journal line
        # could outlive a rolled-back transaction and read as tail
        # truncation). Track the outcome via session events, then flush the
        # staged journal entries once the request handler has finished.
        # Best-effort and no-op unless an audit row was appended AND the
        # journal path is configured.
        #
        # Deep audit 2026-09-28 (C-1): "committed" is sticky — require_user
        # commits its auth read on EVERY authenticated request, and a
        # handler that fails without an explicit rollback() is rolled back
        # by the session close WITHOUT firing after_rollback. The old
        # `committed and not rolled_back` guard therefore flushed staged
        # lines for rows that never committed (e.g. a therapist read whose
        # audit row was appended just before a 413 refusal), and the daily
        # sweep then read the phantom journal-ahead state as "tail
        # truncation" tamper evidence. The fix snapshots the staged-line
        # count at each COMMIT: at request end only the prefix that rode a
        # committed transaction is flushed; anything staged after the last
        # commit belongs to a transaction that never committed and is
        # dropped. A dropped committed line (explicit rollback after a
        # later commit) leaves the journal BEHIND the DB head, which
        # verification treats as benign crash-window semantics.
        committed = False
        rolled_back = False
        staged_at_commit = 0
        committed_audio: list[str] = []

        def _pending_count() -> int:
            info = getattr(session, "info", None)
            pending = (info or {}).get("mindpattern_audit_journal_pending")
            return len(pending) if pending else 0

        def _mark_commit(_session=None) -> None:
            nonlocal committed, staged_at_commit, committed_audio
            committed = True
            staged_at_commit = _pending_count()
            committed_audio = list(session.info.get("mindpattern_audio_deletions_pending", []))

        def _mark_rollback(_session=None) -> None:
            nonlocal rolled_back
            rolled_back = True

        event.listen(session.sync_session, "after_commit", _mark_commit)
        event.listen(session.sync_session, "after_rollback", _mark_rollback)
        try:
            yield session
        except BaseException:
            await session.rollback()
            raise
        finally:
            if committed_audio:
                from .services.audio_store import drain_audio_deletions

                try:
                    # A separate session cannot commit failed request writes.
                    async with request.app.state.sessionmaker() as cleanup_session:
                        await drain_audio_deletions(
                            cleanup_session, request.app.state.settings, identifiers=committed_audio
                        )
                except Exception:
                    import logging

                    logging.getLogger(__name__).exception("post-commit audio cleanup deferred")
            if committed and not rolled_back:
                info = getattr(session, "info", None)
                pending = (info or {}).get("mindpattern_audit_journal_pending") if info else None
                if info is not None and pending is not None and len(pending) > staged_at_commit:
                    # Uncommitted tail (staged after the last commit, never
                    # committed — the silent close-rollback path): keep only
                    # the prefix that rode a committed transaction.
                    info["mindpattern_audit_journal_pending"] = pending[:staged_at_commit]
                try:
                    await flush_audit_journal(
                        session, request.app.state.settings.audit_journal_path
                    )
                except Exception:  # noqa: BLE001 — journal is best-effort by contract
                    import logging

                    logging.getLogger(__name__).exception(
                        "post-commit audit journal flush failed (benign; journal falls behind)"
                    )


async def _authenticate_user(
    request: Request,
    authorization: str | None,
    session: AsyncSession,
    *,
    allow_previous_epoch: bool = False,
) -> User:
    # Every failure is the same flat 401: distinguishing expired / bad
    # signature / unknown user / revoked-token only helps token-lifecycle
    # probing.
    failure = ApiError(status_code=401, detail="invalid token", code="unauthorized")
    if not authorization or not authorization.startswith("Bearer "):
        raise failure
    token = authorization[len("Bearer ") :].strip()
    try:
        payload = tokens.verify_token(token, request.app.state.settings.auth_token_secret)
    except tokens.TokenError:
        raise failure from None
    # ksv (2026-09-26 purpose-split secrets): the signing-secret scheme the
    # token was minted under must equal the live one. A token issued under
    # scheme 1 is dead the moment an operator sets MINDPATTERN_AUTH_TOKEN_SECRET
    # — even when its bytes equal the legacy secret, the rotation is
    # EXPLICIT. Tokens without a ksv claim are legacy and count as scheme 1.
    if payload.get("ksv", 1) != request.app.state.settings.auth_secret_version:
        raise failure
    # Single-token revocation (2026-09-26): a logout records the token's
    # jti until its own exp. Legacy jti-less tokens cannot be individually
    # revoked — they remain covered by the account-wide epoch below.
    # Independent audit 2026-09-27: the check is the durable-backed one —
    # the in-memory map is the fast path, boot hydration keeps it warm, and
    # a point query answers only once the cap has evicted entries.
    jti = payload.get("jti")
    if isinstance(jti, str) and await request.app.state.token_revocations.is_revoked_checked(
        session, jti
    ):
        raise failure
    user = await session.get(User, payload["uid"])
    if user is None or not user.is_active:
        raise failure
    # 2026-10-01 audit L5: the token's purpose claim ("patient"/"therapist")
    # must match the live DB role when present. Nothing branches on it today
    # (every route re-checks user.role), but the claim exists "so future
    # surfaces can skip the DB round-trip" — enforcing it here closes that
    # future gap and kills forged-purpose tokens immediately. An ABSENT
    # claim is pre-2026-09-26 legacy (see tokens.verify_token) and stays
    # accepted; those tokens expire naturally within the 30-day TTL cap.
    claimed_purpose = payload.get("purpose")
    if claimed_purpose is not None:
        expected_purpose = (
            tokens.PURPOSE_THERAPIST if user.role == ROLE_THERAPIST else tokens.PURPOSE_PATIENT
        )
        if claimed_purpose != expected_purpose:
            raise failure
    # Epoch check: logout bumped the account's epoch, retiring every token
    # issued before it — stateless tokens still get a server-side kill switch.
    token_epoch = payload.get("ep", 1)
    valid_epochs = (
        (user.token_epoch, user.token_epoch - 1) if allow_previous_epoch else (user.token_epoch,)
    )
    if token_epoch not in valid_epochs:
        raise failure
    # Expose the authenticated jti for in-fence re-checks (the processing-
    # session mint re-verifies revocation inside the lifecycle fence, the
    # same M-2 staleness rule it applies to the epoch). Real requests
    # always carry Starlette state; direct-call test doubles may not —
    # skip the stash rather than fail an otherwise-authenticated call.
    request_state = getattr(request, "state", None)
    if request_state is not None:
        request_state.mindpattern_token_jti = jti if isinstance(jti, str) else None
        request_state.mindpattern_token_epoch = token_epoch
    # A crashed batch rotation is a durable write fence. No other writer
    # may publish ciphertext or replace a credential between resume attempts.
    # Key delivery is allowed so the exact operation can resume; deletion is
    # the explicit escape hatch for an abandoned account.
    if getattr(request, "method", "GET") not in ("GET", "HEAD", "OPTIONS"):
        path = str(getattr(getattr(request, "url", None), "path", ""))
        if path.startswith("/api/v1/"):
            path = "/api/" + path[len("/api/v1/") :]
        allowed = {
            "/api/processing/rekey",
            "/api/processing/sessions",
            "/api/account",
            "/api/auth/logout",
        }
        allowed.update({"/api/account/llm-consent", "/api/account/voice-consent"})
        if path.startswith("/api/consents/") and (
            request.method == "DELETE" or path.endswith("/share-voice")
        ):
            allowed.add(path)
        if (
            path not in allowed
            and await session.scalar(
                select(RekeyJournal.id).where(RekeyJournal.user_id == user.id).limit(1)
            )
            is not None
        ):
            raise ApiError(
                status_code=409,
                detail="complete the pending key rotation before writing",
                code="rekey_in_progress",
            )
    # End the auth read transaction immediately: the session stays usable
    # (the next query auto-begins), but the pooled connection is NOT pinned
    # open for the rest of the request — a recompute holds no transaction
    # across its seconds of analysis (Postgres pool pressure). Commit, not
    # rollback: rollback would EXPIRE the user object's attributes, and the
    # first later access would hit the DB synchronously (MissingGreenlet
    # under asyncio). Committing a read-only transaction cannot legitimately
    # fail; if it ever does, re-load so callers still get a usable object.
    try:
        await session.commit()
    except Exception:
        await session.rollback()
        user = await session.get(User, payload["uid"]) or user
    return user


async def ensure_no_rekey(session: AsyncSession, user_id: str) -> None:
    """Call inside a writer's fence as well as at request admission."""
    if (
        await session.scalar(
            select(RekeyJournal.id).where(RekeyJournal.user_id == user_id).limit(1)
        )
        is not None
    ):
        raise ApiError(
            status_code=409,
            detail="complete the pending key rotation before writing",
            code="rekey_in_progress",
        )


async def require_user(
    request: Request,
    authorization: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> User:
    return await _authenticate_user(request, authorization, session)


async def require_rekey_retry_user(
    request: Request,
    authorization: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> User:
    """Previous epoch is admitted only for the endpoint's exact cached retry."""
    user = await _authenticate_user(request, authorization, session, allow_previous_epoch=True)
    if user.role != ROLE_USER:
        raise ApiError(
            status_code=403,
            detail="therapist accounts cannot access journal endpoints",
            code="forbidden",
        )
    return user


async def require_regular_user(
    user: User = Depends(require_user),
) -> User:
    """Journal-owner endpoints: a therapist token must not reach them. The
    token authenticated fine — the ROLE is wrong — so this is 403
    (forbidden), not 401; a client that treats 401 as "re-login" would
    otherwise loop a logged-in therapist forever."""
    if user.role != ROLE_USER:
        raise ApiError(
            status_code=403,
            detail="therapist accounts cannot access journal endpoints",
            code="forbidden",
        )
    return user


async def require_therapist(
    user: User = Depends(require_user),
) -> User:
    """Sharing endpoints: only therapist accounts. Same 403-not-401 logic,
    mirrored — a patient token is a valid session with the wrong role."""
    if user.role != ROLE_THERAPIST:
        raise ApiError(
            status_code=403,
            detail="not a therapist account",
            code="forbidden",
        )
    return user


async def require_sharing_enabled(request: Request) -> None:
    """Fail closed when the controlled therapist-sharing feature is off.

    A disabled deployment must not expose either public therapist elevation
    or patient pairing/grant routes. Use a flat 404 rather than advertising
    whether a sensitive feature is merely administratively disabled.
    """
    if not bool(getattr(request.app.state.settings, "therapist_sharing_enabled", False)):
        raise ApiError(status_code=404, detail="not found", code="not_found")
