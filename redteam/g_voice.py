"""Voice-journaling red-team campaign (VOICE_PLAN.md P6, 2026-09-29).

The threat-model additions the voice feature ships with, and the state of
each. Items marked TESTED are pinned in backend/tests/test_audio_api.py,
backend/tests/test_audio_attachments.py, web/tests/audioVoice.test.ts and
mobile/tests/audioVoice.test.ts; the rest are deployment/ops gates this
campaign documents for the next penetration pass.

V-1  Flag-off discovery ................... TESTED  flat 404 on every /audio
        route (auth runs first: anonymous 401, therapist 403 — the
        exhaustive role-wall contract); /meta carries audio_available.
V-2  Consent gate .......................... TESTED  Art. 7 record + policy
        fingerprint; provider/model/retention change makes a recorded yes
        inert (403 voice_consent_required) until re-opt-in.
V-3  Audio persistence ..................... TESTED  the transcription route
        is stateless by construction (no storage path exists in it); only
        explicitly kept, client-encrypted recordings are stored.
V-4  Route-scoped body cap ................. TESTED  /audio bodies answer to
        MINDPATTERN_AUDIO_MAX_BODY_BYTES (default 4 MiB); every other
        route keeps the global 2 MiB; the edge buffer budget is judged on
        the larger cap at boot.
V-5  Rate/cost abuse ....................... TESTED (bucket wiring)  own
        per-user buckets for transcribe (10/h default) and upload (30/h);
        OPERATOR: review before raising — transcription spends third-party
        money.
V-6  Upstream hardening .................... TESTED  https-only (boot-failed
        otherwise), no redirects, trust_env=False, wall-clock deadline,
        1 MiB response cap, upstream bodies never echoed (502 envelope
        only).
V-7  IDOR on attachments ................... TESTED  owner-scoped fetch and
        delete answer a flat 404 to any other account (patient or
        therapist).
V-8  Therapist voice gate .................. TESTED  active consent AND
        share_voice required (403 consent_voice_share_required otherwise,
        including revoked); every SERVED fetch writes an audio_access
        audit row; expired recordings answer 410 and are NOT audited.
V-9  Retention enforcement ................. TESTED  lazy expiry on every
        fetch path + the periodic sweeper (object first, then row); the
        optional 31-day S3 lifecycle rule is the orphan backstop.
V-10 Entry deletion / erasure .............. TESTED  entry delete cascades
        row + object inside the lock; account deletion cascades rows (FK)
        — OPERATOR: enable the S3 lifecycle backstop so orphaned objects
        cannot outlive their rows after an erasure.
V-11 Blob grafting ......................... TESTED (crypto)  audio AAD
        binds (user, entry, audio version): cross-user/cross-entry grafts
        fail closed on every client (web/mobile/portal vectors).
V-12 Storage key injection ................. TESTED  keys are server-
        generated uuid paths; client_entry_id never reaches a path; the
        local store re-verifies root containment on every path.
V-13 At-rest decryption surfaces ........... TESTED (review)  playback
        decrypts in memory and revokes the object URL / deletes the cache
        file; nothing decrypted is cached at rest on any client.
V-14 Timing/pattern side channels .......... OPEN (accepted)  fetch timing
        may reveal attachment existence to the OWNER (their own data) —
        no cross-account oracle exists (V-7).
V-15 Provider prompt injection via audio ... OPEN (accepted)  a crafted
        recording could steer transcript/translation text; the transcript
        is reviewed and EDITABLE by the patient before it is ever stored,
        and analysis-side sanitization is the existing brain/LLM guard
        set (corpus grounding, crisis tiers) — unchanged surface.
V-16 Verifier-gated scope changes .......... TESTED  voice consent and
        share-voice both require the password-equivalent verifier; a
        stolen bearer cannot widen disclosure.

Deployment gates for the operator (production):
  * MINDPATTERN_AUDIO_ENABLED stays OFF until an STT provider, retention
    declaration, and policy version are configured (boot enforces the
    declarations when the URL is set outside development).
  * Dedicated S3 bucket, SSE-S3 default, least-privilege IAM
    (put/get/delete on bucket/audio/* only), 31-day lifecycle backstop.
  * Secrets via _FILE mounts (compose secrets), like every other
    credential-bearing setting.
"""
