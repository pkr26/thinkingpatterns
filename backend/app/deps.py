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

from .models import (
    ROLE_THERAPIST,
    ROLE_USER,
    AccountDeletionTombstone,
    RekeyJournal,
    User,
    utcnow,
)
from .security import tokens
from .security.deletion_tombstone import verifies_deletion_tombstone

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
        # Keep committed evidence separate from the current transaction.
        # Savepoint rollback must discard only its own staged tail; a later
        # retry/commit still publishes. Conversely, savepoint COMMIT is not
        # an outer commit, and an outer rollback must never publish its rows.
        # A post-commit I/O failure cannot undo the request, but keeps
        # readiness unhealthy until a successful flush.
        audit_pending = "mindpattern_audit_journal_pending"
        audio_pending = "mindpattern_audio_deletions_pending"
        committed_audit: list = []
        committed_audio: list[str] = []
        savepoints: dict[object, tuple[int, int]] = {}

        def _savepoint_created(_session, transaction) -> None:
            if transaction.nested:
                savepoints[transaction] = (
                    len(session.info.get(audit_pending, [])),
                    len(session.info.get(audio_pending, [])),
                )

        def _mark_commit(sync_session) -> None:
            if sync_session.in_nested_transaction():
                savepoints.pop(sync_session.get_nested_transaction(), None)
                return
            committed_audit.extend(session.info.pop(audit_pending, []))
            committed_audio.extend(session.info.pop(audio_pending, []))

        def _mark_rollback(_session, transaction) -> None:
            if transaction.nested:
                audit_count, audio_count = savepoints.pop(transaction, (0, 0))
                for name, length in ((audit_pending, audit_count), (audio_pending, audio_count)):
                    if name in session.info:
                        session.info[name] = session.info[name][:length]
            elif transaction.parent is None:
                session.info.pop(audit_pending, None)
                session.info.pop(audio_pending, None)
                savepoints.clear()

        event.listen(session.sync_session, "after_transaction_create", _savepoint_created)
        event.listen(session.sync_session, "after_commit", _mark_commit)
        event.listen(session.sync_session, "after_soft_rollback", _mark_rollback)
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
            if committed_audit:
                # Discard any uncommitted tail, including the implicit
                # rollback performed when the session context closes.
                session.info[audit_pending] = committed_audit
                try:
                    await flush_audit_journal(
                        session,
                        request.app.state.settings.audit_journal_path,
                        failure_observer=request.app.state.metrics.observe_audit_journal_failure,
                    )
                except Exception:  # noqa: BLE001 — action already committed
                    import logging

                    logging.getLogger(__name__).exception(
                        "post-commit audit journal flush failed; readiness remains unhealthy"
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
    # Logical erasure deliberately leaves a scrubbed inactive User row while
    # its large child collections drain in bounded transactions.  Consult the
    # authenticated deletion tombstone for both that state and the final
    # physically-deleted state so offline clients receive the same explicit
    # account-death signal throughout the purge.
    if user is None or not user.is_active:
        tombstone = await session.get(AccountDeletionTombstone, payload["uid"])
        if tombstone is not None:
            expected_purpose = (
                tokens.PURPOSE_THERAPIST
                if tombstone.role == ROLE_THERAPIST
                else tokens.PURPOSE_PATIENT
            )
            claimed_purpose = payload.get("purpose")
            try:
                tombstone_valid = verifies_deletion_tombstone(
                    tombstone,
                    secret=request.app.state.settings.auth_token_secret,
                    auth_secret_version=request.app.state.settings.auth_secret_version,
                    now=utcnow(),
                )
            except (AttributeError, TypeError, ValueError):
                tombstone_valid = False
            if (
                tombstone_valid
                and payload.get("ep", 1) == tombstone.token_epoch
                and (claimed_purpose is None or claimed_purpose == expected_purpose)
            ):
                raise ApiError(
                    status_code=410,
                    detail="account no longer exists",
                    code="account_deleted",
                )
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
            "/api/account/step-up",
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


async def require_therapist_account(
    user: User = Depends(require_user),
) -> User:
    """Role-only therapist gate for enrollment and own-account surfaces."""
    if user.role != ROLE_THERAPIST:
        raise ApiError(
            status_code=403,
            detail="not a therapist account",
            code="forbidden",
        )
    return user


async def require_therapist(
    user: User = Depends(require_therapist_account),
) -> User:
    """Patient-data gate: therapist accounts must complete MFA enrollment."""
    if user.totp_enabled is not True:
        raise ApiError(
            status_code=403,
            detail="multi-factor enrollment is required before accessing patient data",
            code="mfa_enrollment_required",
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
