"""The mini-brain endpoints.

Flow: the client opens a processing session (delivering its data key over
TLS into the memory-only keystore), then triggers a recompute. Inside the
secure processing context entries AND the previous brain state are
decrypted, the stateful brain folds the corpus into its persistent
pattern store (lifecycle, decayed evidence, statistically gated
detectors), and the updated state plus the surfaced patterns are
re-encrypted under the same key. Buffers the enclave owns are zeroized,
and the API-layer copy of the data key is scrubbed in a ``finally`` on
every recompute exit (success or error); immutable str copies the parser
and analyzer produce still linger until GC — see the enclave module for
the honest scope. Sessions are single-use: the key is destroyed the
moment a recompute consumes it.

Two encrypted insight rows come out of a recompute:
  * kind="brain"    — the mini-brain's persistent state (carried forward),
  * kind="patterns" — the surfaced-pattern payload clients decrypt/render.

Threshold honesty (this is the claim the old code broke): while the account
is in the baseline phase NOTHING is decrypted — no key is required, no
analyzer runs, no processing session is consumed. Pattern analysis (brain
or LLM) only ever happens after the configured active-day threshold, and
the LLM path additionally requires the user's explicit per-account consent.

Database-transaction discipline: a recompute never holds a transaction
across analysis. Reads (threshold dates, the capped corpus, the prior brain
state) run in one short transaction that is closed BEFORE the CPU work;
results are written in a second short transaction opened after it. Seconds
of analysis with an open transaction would pin a pooled connection per
in-flight recompute (and on PostgreSQL could hold locks/snapshot state the
vacuum and other requests wait behind).
"""

from __future__ import annotations

import base64
import binascii
import json
import math
from dataclasses import replace
from datetime import date as date_type, timedelta

import anyio.to_thread
from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import make_rate_limiter
from ..deps import ApiError, get_session, require_regular_user
from ..locks import UserLocks
from ..models import Entry, Insight, User, new_id, utcnow
from ..schemas import (
    InsightsResponse,
    ProcessingSessionRequest,
    ProcessingSessionResponse,
    QuestionResponse,
    RecomputeResponse,
)
from ..security import crypto
from ..security.crypto import TamperError
from ..security.enclave import KeyNotFound, SecureProcessingContext, zeroize
from ..services import brain, llm, questions, threshold
from ..services.patterns import JournalEntry
from ..services.threshold import Phase

router = APIRouter(tags=["insights"])

# Two concurrent recomputes for one account would interleave their
# delete-then-insert on the same insight rows (last writer wins, and the
# carried-forward brain state each decrypted may already be stale). The
# deployment is single-process, so an in-process per-user lock serializes
# them; distinct users still recompute in parallel.
_recompute_locks = UserLocks()

# Daily question rows accumulate one per recompute day; bound their history
# inside the recompute write transaction (they are encrypted day-questions,
# not data the user asked to keep forever).
QUESTION_RETENTION_DAYS = 90


def _decode_b64(value: str, what: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(status_code=422, detail=f"{what} must be base64", code="validation_error")


def _dialect_insert(session: AsyncSession):
    """The insert() class with on_conflict_do_update for the session's
    dialect — both sqlite and postgresql ship one; the generic
    sqlalchemy.insert() does not."""
    if session.bind.dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    return insert


async def _replace_insight(
    session: AsyncSession, user_id: str, kind: str, for_date: date_type | None, blob: bytes
) -> None:
    """Write the current insight of (user, kind[, for_date]) idempotently.

    Dated rows (the daily question) UPSERT on the
    uq_insights_user_kind_date constraint, so a repeated same-day recompute
    rewrites in place instead of delete+insert. Rows with for_date=None
    (the patterns payload, the brain state) can never upsert: SQL NULLs are
    distinct, so the unique constraint never sees a conflict for them. They
    stay delete-then-insert under the per-user recompute lock — and the
    delete covers the whole kind, so legacy dated rows of that kind are
    cleaned up too.
    """
    if for_date is None:
        await session.execute(
            delete(Insight).where(Insight.user_id == user_id, Insight.kind == kind)
        )
        session.add(Insight(user_id=user_id, kind=kind, for_date=None, blob=blob))
        return
    now = utcnow()
    stmt = (
        _dialect_insert(session)(Insight)
        .values(
            id=new_id(), user_id=user_id, kind=kind, for_date=for_date, blob=blob, created_at=now
        )
        .on_conflict_do_update(
            index_elements=["user_id", "kind", "for_date"],
            set_={"blob": blob, "created_at": now},
        )
    )
    await session.execute(stmt)


def _is_fk_violation(exc: IntegrityError) -> bool:
    """The insight write lost its parent user row: DELETE /account committed
    while the recompute was analyzing. Surfaces as 410, never a bare 500."""
    orig = getattr(exc, "orig", None)
    if orig is None:
        return False
    # 23503 foreign_key_violation: psycopg-style drivers expose pgcode,
    # asyncpg exposes sqlstate.
    if getattr(orig, "pgcode", None) == "23503" or getattr(orig, "sqlstate", None) == "23503":
        return True
    return "foreign key" in str(orig).lower()


@router.post(
    "/processing/sessions",
    response_model=ProcessingSessionResponse,
    status_code=201,
    dependencies=[Depends(make_rate_limiter("processing-sessions", "processing_rate_limit", "processing_rate_window"))],
)
async def create_processing_session(
    body: ProcessingSessionRequest,
    request: Request,
    user: User = Depends(require_regular_user),
):
    data_key = _decode_b64(body.data_key, "data_key")
    if len(data_key) != crypto.KEY_SIZE:
        raise ApiError(
            status_code=422,
            detail=f"data_key must be {crypto.KEY_SIZE} bytes",
            code="validation_error",
        )
    settings = request.app.state.settings
    token = request.app.state.key_store.create(
        data_key, settings.processing_session_ttl, owner=user.id
    )
    return ProcessingSessionResponse(session_token=token, expires_in=settings.processing_session_ttl)


# The analysis cost of an entry scales with its *text bytes* (MinHash signs
# every shingle; the topic scan allocates per token). Blob/quota limits bound
# storage, not CPU — these bound what one recompute is ever asked to chew on.
MAX_ANALYSIS_TEXT_CHARS = 20_000  # per entry (journal entries are far smaller)
MAX_ANALYSIS_TOTAL_CHARS = 2_000_000  # per recompute; oldest text truncated first
# The brain runs on the SERVER-VALIDATED outer entry_date, never on the
# client-controlled created_at inside the encrypted payload. The inner date is
# only sanity-checked (parses, within a day of the outer date, so timezone
# skew between the client's clock and the server's cannot reject honest
# entries) — a year-3000 inner date used to reach the decay math and overflow
# every recompute from then on.
INNER_DATE_TOLERANCE_DAYS = 1

# Payload-shape failures: the ciphertext authenticated but the plaintext is
# semantically malformed (bad JSON, wrong types, impossible dates). Both the
# primary run and the amnesia retry translate these to the same 400 — the
# retry used to catch only TamperError, so a malformed entry surfaced as a
# 500 exactly when the state blob was ALSO tampered. OverflowError is a
# backstop behind the date validation above.
_ENTRY_MALFORMED = (json.JSONDecodeError, KeyError, UnicodeDecodeError, ValueError, TypeError, OverflowError)


def _parse_entries(
    plains: list[bytearray], outer_dates: list[date_type]
) -> list[JournalEntry]:
    entries: list[JournalEntry] = []
    for raw, outer in zip(plains, outer_dates):
        payload = json.loads(raw.decode("utf-8"))
        text = payload["text"]
        if not isinstance(text, str):
            raise ValueError("text must be a string")
        if len(text) > MAX_ANALYSIS_TEXT_CHARS:
            text = text[:MAX_ANALYSIS_TEXT_CHARS]
        sentiment = payload.get("sentiment")
        if sentiment is not None:
            # NaN/Infinity parse fine in Python's json and would poison
            # every average downstream — reject them here, clamp the rest
            # to the engine's [-1, 1] scale. bool is an int subclass in
            # Python but `true` is not a mood tag.
            if isinstance(sentiment, bool) or not isinstance(sentiment, (int, float)) or not math.isfinite(sentiment):
                raise ValueError("sentiment must be a finite number")
            sentiment = max(-1.0, min(1.0, float(sentiment)))
        inner = date_type.fromisoformat(payload["created_at"])
        if abs((inner - outer).days) > INNER_DATE_TOLERANCE_DAYS:
            raise ValueError("created_at does not match entry_date")
        entries.append(
            JournalEntry(
                text=text,
                entry_date=outer,
                sentiment=sentiment,
            )
        )
    # Total-corpus budget: keep the most recent text (entries arrive in
    # date order) and truncate the oldest beyond the budget. JournalEntry
    # is frozen, so truncation swaps in a copy rather than mutating.
    total = sum(len(e.text) for e in entries)
    for i, entry in enumerate(entries):
        if total <= MAX_ANALYSIS_TOTAL_CHARS:
            break
        total -= len(entry.text)
        entries[i] = replace(entry, text="")
    return entries


async def _load_rows(session: AsyncSession, user_id: str, limit: int) -> list[Entry]:
    """The most recent ``limit`` entries, in chronological order.

    Bounded in SQL — ORDER BY recency DESC, LIMIT, then reversed in Python
    — instead of fetching EVERY blob the account holds and slicing
    rows[-limit:]: at the 10k-entry / 256 MiB quota the old shape pulled
    hundreds of MiB over the wire to keep the newest 2000 rows.
    """
    rows = list(
        (
            await session.execute(
                select(Entry)
                .where(Entry.user_id == user_id)
                .order_by(Entry.entry_date.desc(), Entry.received_at.desc(), Entry.id.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    rows.reverse()
    return rows


async def _entry_dates(session: AsyncSession, user_id: str) -> list[date_type]:
    """Distinct active dates for the threshold evaluation — an index-only
    scan over ix_entries_user_date (no row, and no ciphertext, is fetched)."""
    return list(
        (
            await session.execute(
                select(Entry.entry_date)
                .distinct()
                .where(Entry.user_id == user_id)
                .order_by(Entry.entry_date.asc())
            )
        )
        .scalars()
        .all()
    )


async def _latest_insight(session: AsyncSession, user_id: str, kind: str) -> Insight | None:
    return (
        (
            await session.execute(
                select(Insight)
                .where(Insight.user_id == user_id, Insight.kind == kind)
                .order_by(Insight.created_at.desc(), Insight.id.desc())
                .limit(1)
            )
        )
        .scalars()
        .first()
    )


@router.post(
    "/insights/recompute",
    response_model=RecomputeResponse,
    dependencies=[Depends(make_rate_limiter("insights-recompute", "processing_rate_limit", "processing_rate_window"))],
)
async def recompute(
    request: Request,
    user: User = Depends(require_regular_user),
    x_processing_token: str | None = Header(default=None),
):
    settings = request.app.state.settings
    key_store = request.app.state.key_store
    sessionmaker = request.app.state.sessionmaker

    # Phase comes from plaintext DB dates — no decryption, no key needed.
    # Load ONLY the distinct dates here: a baseline-phase recompute must not
    # pull the account's whole ciphertext corpus (potentially hundreds of
    # MiB) into memory just to answer "still 12 days to go".
    async with sessionmaker() as session:
        date_rows = await _entry_dates(session, user.id)
    if not date_rows:
        raise ApiError(status_code=400, detail="no entries to analyze", code="bad_request")

    state = threshold.evaluate(date_rows, settings.unlock_threshold_days)
    today = date_type.today()

    if state.phase is not Phase.INSIGHT:
        # BASELINE: reveal nothing, decrypt nothing, analyze nothing. Any
        # session token the client opened is consumed (destroyed) so the
        # keystore does not hold an unused key for the rest of the TTL.
        if x_processing_token:
            key_store.destroy(x_processing_token)
        return RecomputeResponse(
            phase=state.phase.value,
            active_days=state.active_days,
            streak=state.streak,
            days_remaining=state.days_remaining,
            patterns_stored=0,
            question_stored=False,
            analyzer="none",
        )

    # ---- insight phase: key required, session single-use -------------------
    if not x_processing_token:
        raise ApiError(
            status_code=401,
            detail="missing processing session token",
            code="processing_session_required",
        )
    try:
        # The session is bound to the account that opened it: a token minted
        # for one user can never steer a recompute for another. pop() is an
        # ATOMIC consume — single-use by mechanism, not by the absence of an
        # await between get() and destroy().
        data_key = key_store.pop(x_processing_token, owner=user.id)
    except KeyNotFound:
        raise ApiError(
            status_code=403,
            detail="processing session missing or expired",
            code="processing_session_invalid",
        ) from None

    # The popped key is a bytearray the keystore no longer references; it
    # is scrubbed in the finally below on EVERY exit from the recompute —
    # success, 400, 410, or an unexpected 500 alike. (str copies the parser
    # and analyzer make are immutable and still linger until GC — see the
    # enclave module docstring for what zeroization honestly covers.)
    try:
        async with _recompute_locks.hold(f"insights:{user.id}"):
            # READ phase: one short transaction, closed by the context
            # manager BEFORE any analysis runs. Only plain values (blobs as
            # immutable bytes, dates, ids) leave the session.
            async with sessionmaker() as session:
                rows = await _load_rows(session, user.id, settings.recompute_entry_limit)
                # The SERVER-validated outer dates drive the brain's calendar;
                # the client-controlled created_at inside each blob is only
                # sanity-checked.
                analysis_dates = [row.entry_date for row in rows]
                # The brain's memory from the previous recompute travels INTO
                # the secure context as one more encrypted item and comes back
                # out updated.
                prior = await _latest_insight(session, user.id, "brain")
                entry_items = [
                    (crypto.build_aad("entry", row.user_id, row.client_entry_id), bytes(row.blob))
                    for row in rows
                ]
                state_item = (
                    (crypto.build_aad("insights", user.id, "brain"), bytes(prior.blob))
                    if prior
                    else None
                )
            analyzer = llm.get_analyzer(settings, llm_consent=user.llm_consent)

            def make_analyze_fn(with_state: bool):
                # A factory, not a plain closure: the tamper-retry below passes the
                # entry items WITHOUT the state blob, and a closure over a truthy
                # state_item would strip the newest ENTRY as "state" on that path.
                def analyze_fn(plains: list[bytearray]):
                    state_plain, entry_plains = (
                        (bytes(plains[-1]), plains[:-1]) if with_state else (None, plains)
                    )
                    entries = _parse_entries(entry_plains, analysis_dates)
                    result = brain.update(brain.load_state(state_plain), entries, today)
                    merged = list(result.surfaced)
                    if isinstance(analyzer, llm.LLMAnalyzer):
                        seen = {(p.kind, p.label) for p in merged}
                        for extra in analyzer.extract_patterns(entries):
                            if (extra.kind, extra.label) not in seen:
                                merged.append(extra)
                        merged = merged[: brain.MAX_SURFACED]
                    return result, merged

                return analyze_fn

            encrypted = entry_items + ([state_item] if state_item else [])
            # Analysis runs on a DEDICATED capacity limiter, not the shared anyio
            # thread pool: recomputes are attacker-sized multi-second CPU work and
            # must never queue in front of login scrypt (or any other request's
            # worker) in the same FIFO pool. No DB session is open here.
            analyze_limiter = getattr(request.app.state, "analyze_limiter", None)
            try:
                # Decryption + analysis is synchronous, potentially slow CPU (or an
                # LLM round-trip); run it in a worker thread so the event loop that
                # serves every other request never stalls behind a recompute.
                result, merged = await anyio.to_thread.run_sync(
                    SecureProcessingContext(data_key).run, encrypted, make_analyze_fn(state_item is not None),
                    limiter=analyze_limiter,
                )
            except TamperError:
                if state_item is None:
                    raise ApiError(
                        status_code=400,
                        detail="entry blob failed authentication",
                        code="entry_blob_invalid",
                    ) from None
                # A tampered/corrupt brain state must not brick the account forever:
                # retry once with amnesia (fresh state, the same capped entry
                # corpus) — if an ENTRY blob is the culprit the retry fails the
                # same way and surfaces the real error.
                try:
                    result, merged = await anyio.to_thread.run_sync(
                        SecureProcessingContext(data_key).run, entry_items, make_analyze_fn(False),
                        limiter=analyze_limiter,
                    )
                except TamperError:
                    raise ApiError(
                        status_code=400,
                        detail="entry blob failed authentication",
                        code="entry_blob_invalid",
                    ) from None
                except _ENTRY_MALFORMED:
                    # The state was tampered AND an entry payload is bad JSON
                    # (AEAD-valid): same 400 the primary path would give.
                    raise ApiError(
                        status_code=400,
                        detail="entry payload malformed",
                        code="entry_payload_malformed",
                    ) from None
            except _ENTRY_MALFORMED:
                # No exception-text echo: parser internals can quote payload content.
                raise ApiError(
                    status_code=400,
                    detail="entry payload malformed",
                    code="entry_payload_malformed",
                ) from None

            insights_payload = {
                "v": 2,
                "phase": state.phase.value,
                "stats": {**result.stats, "patterns": [p.to_dict() for p in merged]},
            }
            blob = crypto.encrypt(
                data_key,
                json.dumps(insights_payload).encode("utf-8"),
                crypto.build_aad("insights", user.id, "patterns"),
            )
            state_blob = crypto.encrypt(
                data_key,
                brain.dump_state(result.new_state),
                crypto.build_aad("insights", user.id, "brain"),
            )
            question_blob = None
            if merged:
                question = questions.question_for_today(user.id, merged, today)
                question_payload = {"for_date": today.isoformat(), "question": question}
                question_blob = crypto.encrypt(
                    data_key,
                    json.dumps(question_payload).encode("utf-8"),
                    crypto.build_aad("question", user.id, today.isoformat()),
                )

            # WRITE phase: a second short transaction, opened only after the
            # analysis and encryption are done. Nothing here decrypts.
            async with sessionmaker() as session:
                try:
                    await _replace_insight(session, user.id, "patterns", None, blob)
                    await _replace_insight(session, user.id, "brain", None, state_blob)
                    question_stored = False
                    if question_blob is not None:
                        await _replace_insight(session, user.id, "question", today, question_blob)
                        question_stored = True
                    # Retention: age out dated question history past the
                    # window (today's upsert above is never affected).
                    await session.execute(
                        delete(Insight).where(
                            Insight.user_id == user.id,
                            Insight.kind == "question",
                            Insight.for_date < today - timedelta(days=QUESTION_RETENTION_DAYS),
                        )
                    )
                    await session.commit()
                except IntegrityError as exc:
                    if _is_fk_violation(exc):
                        # DELETE /account committed while we were analyzing:
                        # the FK killed the insight insert. The account is
                        # gone — 410, not a bare 500.
                        raise ApiError(
                            status_code=410,
                            detail="account no longer exists",
                            code="account_deleted",
                        ) from None
                    raise
            return RecomputeResponse(
                phase=state.phase.value,
                active_days=state.active_days,
                streak=state.streak,
                days_remaining=state.days_remaining,
                patterns_stored=len(merged),
                question_stored=question_stored,
                analyzer="llm" if isinstance(analyzer, llm.LLMAnalyzer) else "brain",
                patterns_new=result.patterns_new,
                patterns_fading=result.patterns_fading,
            )
    finally:
        zeroize(data_key)


@router.get(
    "/insights",
    response_model=InsightsResponse,
    dependencies=[Depends(make_rate_limiter("insights-read", "read_rate_limit", "read_rate_window"))],
)
async def get_insights(
    request: Request,
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
):
    # Same configured threshold as /insights/recompute, or the summary and
    # the stored blob disagree about the user's phase. Distinct dates only —
    # the index serves this without touching row data.
    rows = await _entry_dates(session, user.id)
    state = threshold.evaluate(rows, request.app.state.settings.unlock_threshold_days)
    latest = await _latest_insight(session, user.id, "patterns")
    return InsightsResponse(
        phase=state.phase.value,
        active_days=state.active_days,
        streak=state.streak,
        days_remaining=state.days_remaining,
        blob=base64.b64encode(bytes(latest.blob)).decode("ascii") if latest else None,
    )


@router.get(
    "/questions/today",
    response_model=QuestionResponse,
    dependencies=[Depends(make_rate_limiter("questions-read", "read_rate_limit", "read_rate_window"))],
)
async def get_question_today(
    user: User = Depends(require_regular_user),
    session: AsyncSession = Depends(get_session),
):
    today = date_type.today()
    row = (
        await session.execute(
            select(Insight)
            .where(Insight.user_id == user.id, Insight.kind == "question", Insight.for_date == today)
            .order_by(Insight.created_at.desc(), Insight.id.desc())
            .limit(1)
        )
    ).scalars().first()
    if row is None:
        raise ApiError(
            status_code=404,
            detail="no question for today; open a processing session and run /insights/recompute",
            code="not_found",
        )
    return QuestionResponse(
        for_date=row.for_date or today,
        blob=base64.b64encode(bytes(row.blob)).decode("ascii"),
    )
