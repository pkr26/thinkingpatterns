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
import time
from dataclasses import replace
from datetime import date as date_type, timedelta

import anyio.to_thread
from fastapi import APIRouter, Depends, Header, Request, Body
from sqlalchemy import delete, func, select
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
# Flattened once: Python 3.14 rejects the nested except (TamperError,
# _ENTRY_MALFORMED) form.
_TAMPER_OR_MALFORMED = (TamperError, *_ENTRY_MALFORMED)


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
        # --- structured channels (payload v2, 2026-09-17). All optional;
        # every field is validated as hostile input exactly like sentiment:
        # malformed values are a 400 (entry_payload_malformed), never a
        # silent default that would quietly mislabel the analysis.
        energy = payload.get("energy")
        if energy is not None:
            if isinstance(energy, bool) or not isinstance(energy, (int, float)) or not math.isfinite(energy):
                raise ValueError("energy must be a finite number")
            energy = max(-1.0, min(1.0, float(energy)))
        sleep_raw = payload.get("sleep")
        if sleep_raw is not None:
            if isinstance(sleep_raw, bool) or not isinstance(sleep_raw, int) or not 1 <= sleep_raw <= 5:
                raise ValueError("sleep must be an integer 1..5")
        tags_raw = payload.get("tags")
        tags: tuple[str, ...] = ()
        if tags_raw is not None:
            if not isinstance(tags_raw, list) or len(tags_raw) > 8:
                raise ValueError("tags must be a list of at most 8 strings")
            cleaned = []
            for tag in tags_raw:
                if not isinstance(tag, str):
                    raise ValueError("tags must be strings")
                cleaned_tag = tag.strip().lower()[:24]
                if cleaned_tag and cleaned_tag not in cleaned:
                    cleaned.append(cleaned_tag)
            tags = tuple(cleaned)
        entries.append(
            JournalEntry(
                text=text,
                entry_date=outer,
                sentiment=sentiment,
                energy=energy,
                sleep_quality=sleep_raw,
                tags=tags,
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


def _chosen_pattern_pid(today: date_type, patterns: list, user_id: str) -> str | None:
    """The pid of the pattern whose question was selected for today.

    Deterministic re-derivation of the same choice questions.question_for_today
    made (same pool, same rotation): build_pool's ordering is stable, so the
    pool index maps back to its pattern. Falls back to None when the day's
    question is generic.
    """
    from ..services import questions as question_engine

    # Mirror build_pool EXACTLY: top-5 by feedback rank FIRST, sensitive
    # patterns skipped AFTER the slice. Filtering before the slice admits
    # different patterns into the pool and misattributes taps to the wrong
    # pattern whenever a sensitive pattern ranks in the top 5.
    pool_patterns = [
        p for p in sorted(patterns, key=question_engine.feedback_rank)[:question_engine.MAX_PATTERN_QUESTIONS]
        if not question_engine.pattern_is_sensitive(p)
    ]
    rendered: list[str | None] = []
    owners: list[str | None] = []
    for p in pool_patterns:
        for q in question_engine.render_pattern_questions(p):
            rendered.append(q)
            owners.append(p.detail.get("pattern_pid") if isinstance(p.detail, dict) else None)
    generic = list(question_engine.GENERIC_QUESTIONS)
    rendered.extend(generic)
    owners.extend([None] * len(generic))
    # Mirror build_pool's dedupe + suppression filters.
    filtered: list[tuple[str | None, str]] = []
    seen: set[str] = set()
    for owner, q in zip(owners, rendered):
        if q in seen or question_engine.crisis.matches_suppress(q):
            continue
        seen.add(q)
        filtered.append((owner, q))
    pool = [q for _, q in filtered] or list(generic)
    index = (today.toordinal() + question_engine.user_rotation_offset(user_id)) % len(pool)
    chosen_owner = filtered[index][0] if index < len(filtered) else None
    return chosen_owner if isinstance(chosen_owner, str) else None


def _parse_feedback(raw: bytes) -> list[tuple[str, bool]]:
    """Decoded question-feedback taps: [{"pid": str, "resonated": bool}].
    Hostile-shape rules like every payload: malformed input is a 400
    (entry_payload_malformed), never a silent skip or a crash."""
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ApiError(
            status_code=400,
            detail="feedback blob is malformed",
            code="entry_payload_malformed",
        ) from exc
    events = payload.get("feedback") if isinstance(payload, dict) else None
    if not isinstance(events, list):
        raise ApiError(
            status_code=400,
            detail="feedback blob is malformed",
            code="entry_payload_malformed",
        )
    out: list[tuple[str, bool]] = []
    for item in events[:100]:
        if not isinstance(item, dict):
            continue
        pid = item.get("pid")
        resonated = item.get("resonated")
        if isinstance(pid, str) and 1 <= len(pid) <= 128 and isinstance(resonated, bool):
            out.append((pid, resonated))
    return out


async def _load_rows(
    session: AsyncSession, user_id: str, limit: int, blob_budget: int
) -> list[Entry]:
    """The most recent ``limit`` entries, in chronological order, within a
    cumulative ciphertext byte budget.

    Bounded in SQL — ORDER BY recency DESC, LIMIT, then reversed in Python
    — instead of fetching EVERY blob the account holds and slicing
    rows[-limit:]: at the 10k-entry / 256 MiB quota the old shape pulled
    hundreds of MiB over the wire to keep the newest 2000 rows.

    The byte budget (2026-09-17) is the second bound: rows are fetched in
    two phases — ids + sizes first, then only the NEWEST rows whose
    running ciphertext total stays within ``blob_budget`` — so peak
    recompute memory is bounded by the ANALYSIS budget, never by the
    account's storage quota. A quota-maxed account can no longer make one
    process transiently hold ~256 MiB ciphertext + plaintext + zeroized
    copies (x4 concurrent analyze slots) for the sake of a 2M-char
    analysis. Rows beyond the budget are dropped oldest-first, exactly
    like the per-recompute text truncation they sit beneath.
    """
    recency = (
        Entry.entry_date.desc(), Entry.received_at.desc(), Entry.id.desc()
    )
    id_rows = (
        await session.execute(
            select(Entry.id, func.length(Entry.blob).label("size"))
            .where(Entry.user_id == user_id)
            .order_by(*recency)
            .limit(limit)
        )
    ).all()
    kept: list[str] = []
    budget = blob_budget
    for row_id, size in id_rows:
        if size is None or size > budget:
            break  # oldest rows are beyond the analysis budget: not fetched
        kept.append(row_id)
        budget -= size
    if not kept:
        return []
    rows = list(
        (
            await session.execute(
                select(Entry)
                .where(Entry.id.in_(kept))
                .order_by(Entry.entry_date.asc(), Entry.received_at.asc(), Entry.id.asc())
            )
        )
        .scalars()
        .all()
    )
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
    feedback_blob: str | None = Body(default=None, embed=True),
):
    """``feedback_blob`` (2026-09-17): optional base64 AES-GCM blob holding
    the user's question-feedback taps ({"feedback": [{pid, resonated}]}),
    AAD-bound to ("feedback", user id) — opaque like every other payload,
    decrypted only inside the secure processing context, consumed by the
    brain's feedback-aware question ranking."""
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
                rows = await _load_rows(
                    session, user.id, settings.recompute_entry_limit,
                    settings.analysis_blob_budget,
                )
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
            enricher = llm.get_enricher(settings, llm_consent=user.llm_consent)

            def make_analyze_fn(with_state: bool, with_feedback: bool):
                # A factory, not a plain closure: the tamper-retry below passes
                # different item TAILS (without the state blob, or without the
                # feedback blob), and a closure over the truthy originals would
                # strip the wrong plaintexts as "state"/"feedback" on those
                # paths.
                def analyze_fn(plains: list[bytearray]):
                    tail = (1 if with_state else 0) + (1 if with_feedback else 0)
                    entry_plains = plains[:-tail] if tail else plains
                    state_plain = bytes(plains[-tail]) if with_state and tail else None
                    fb_plain = bytes(plains[-1]) if with_feedback else None
                    entries = _parse_entries(entry_plains, analysis_dates)
                    feedback_events = _parse_feedback(fb_plain) if fb_plain is not None else []
                    result = brain.update(brain.load_state(state_plain), entries, today,
                                          feedback=feedback_events or None)
                    merged = list(result.surfaced)
                    if enricher is not None:
                        # Brain-first inversion (2026-09-17): the model
                        # receives the deterministic findings and can only
                        # attach a sanitized narrative to them — its output
                        # replaces a finding's detail (narrative added),
                        # never mints a new claim.
                        narrated = {(p.kind, p.label): p for p in enricher.extract_patterns(entries, findings=merged)}
                        merged = [narrated.get((p.kind, p.label), p) for p in merged]
                        merged = merged[: brain.MAX_SURFACED]
                    return result, merged

                return analyze_fn

            feedback_item = (
                # Same 4xx discipline as every other payload: bad base64 is
                # a client bug, not a 500, and must not echo payload bytes.
                (crypto.build_aad("feedback", user.id),
                 _decode_b64(feedback_blob, "feedback_blob"))
                if feedback_blob
                else None
            )
            encrypted = entry_items + ([state_item] if state_item else []) + ([feedback_item] if feedback_item else [])
            # Analysis runs on a DEDICATED capacity limiter, not the shared anyio
            # thread pool: recomputes are attacker-sized multi-second CPU work and
            # must never queue in front of login scrypt (or any other request's
            # worker) in the same FIFO pool. No DB session is open here.
            analyze_limiter = getattr(request.app.state, "analyze_limiter", None)
            metrics = getattr(request.app.state, "metrics", None)
            started = time.monotonic()
            try:
                # Decryption + analysis is synchronous, potentially slow CPU (or an
                # LLM round-trip); run it in a worker thread so the event loop that
                # serves every other request never stalls behind a recompute.
                result, merged = await anyio.to_thread.run_sync(
                    SecureProcessingContext(data_key).run, encrypted,
                    make_analyze_fn(state_item is not None, feedback_item is not None),
                    limiter=analyze_limiter,
                )
            except TamperError:
                if state_item is None and feedback_item is None:
                    raise ApiError(
                        status_code=400,
                        detail="entry blob failed authentication",
                        code="entry_blob_invalid",
                    ) from None
                # Isolate the culprit before touching the brain state: retry
                # with entries + state but WITHOUT the feedback item. If that
                # succeeds, the (client-controlled) feedback blob was the
                # tampered one — a 400 with its own code, never a state wipe.
                # A tampered/corrupt brain state must not brick the account
                # forever: retry once with amnesia (fresh state, the same
                # capped entry corpus) — if an ENTRY blob is the culprit the
                # retry fails the same way and surfaces the real error.
                try:
                    result, merged = await anyio.to_thread.run_sync(
                        SecureProcessingContext(data_key).run,
                        entry_items + ([state_item] if state_item else []),
                        make_analyze_fn(state_item is not None, False),
                        limiter=analyze_limiter,
                    )
                except _TAMPER_OR_MALFORMED:
                    # Still failing without the feedback item: either an entry
                    # blob or the state itself — the amnesia retry (entries
                    # only) distinguishes them exactly as before.
                    try:
                        result, merged = await anyio.to_thread.run_sync(
                            SecureProcessingContext(data_key).run, entry_items, make_analyze_fn(False, False),
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
                else:
                    # entries+state decrypted cleanly: the feedback blob was
                    # the tampered item. The client must quarantine its
                    # feedback queue (it can never authenticate), not wipe
                    # state and not silently drop the taps.
                    raise ApiError(
                        status_code=400,
                        detail="feedback blob failed authentication",
                        code="feedback_blob_invalid",
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
                question_payload = {
                    "for_date": today.isoformat(),
                    "question": question,
                    # The chosen pattern's stable id (when the question came
                    # from a pattern): routes the "did this land?" taps back
                    # to the right brain record. Absent for generic days.
                    "pattern_pid": _chosen_pattern_pid(today, merged, user.id),
                }
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
            if metrics is not None:
                metrics.observe_recompute(time.monotonic() - started)
                if enricher is not None:
                    metrics.observe_llm(failed=enricher.last_error is not None)
            return RecomputeResponse(
                phase=state.phase.value,
                active_days=state.active_days,
                streak=state.streak,
                days_remaining=state.days_remaining,
                patterns_stored=len(merged),
                question_stored=question_stored,
                # Honest analyzer reporting: "llm" only when the enricher
                # exists AND its last call actually succeeded (a failed
                # endpoint contributed nothing — the response must not
                # claim it ran).
                analyzer=(
                    "llm"
                    if enricher is not None and enricher.last_error is None
                    else "brain"
                ),
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
