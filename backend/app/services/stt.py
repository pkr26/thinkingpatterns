"""Optional consent-gated SPEECH-TO-TEXT layer (VOICE_PLAN.md, 2026-09-29).

This is the module that can ship recorded audio off-server, so it follows
the same no-benefit-of-the-doubt discipline as services/llm.py:

  * The caller (api/audio.py) only reaches this path with the feature
    flag on AND a consent record that matches the CURRENT policy
    fingerprint — enforced there, not trusted here.
  * Audio plaintext exists in this process for the duration of ONE
    upstream call. It is never written to disk, object storage, the
    database, logs, or metrics; only its byte length is ever observed.
  * The provider URL is https-only (loopback http allowed in development
    exactly like MINDPATTERN_LLM_URL), redirects are refused, ambient
    proxy/CA configuration is ignored (trust_env=False), and responses
    are size-capped and wall-clock bounded.
  * Provider output is treated as hostile text: control characters are
    stripped and lengths are capped before anything is returned to the
    client.

English translation rides the EXISTING chat-completions client
(services/llm.py LLMAnalyzer) rather than a second audio pass: half the
provider cost, one consent surface, and the same bounded-POST guards.
When the LLM endpoint is unconfigured, translation degrades to None —
the original transcript alone is still fully functional.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from dataclasses import dataclass

from ..config import Settings

logger = logging.getLogger("mindpattern.stt")

# Version of the disclosure copy the client shows in the voice-consent
# flow. Same GDPR Art. 7 standing as llm.LLM_DISCLOSURE_VERSION: bump it
# whenever the copy changes; it is folded into the policy fingerprint so
# a consent recorded against older copy goes inert until re-opt-in.
STT_DISCLOSURE_VERSION = "v1"

# A five-minute take transcribes in well under a minute on the providers
# this is pointed at, but the budget must cover a cold provider queue.
# Same double-bound structure as the LLM client: httpx per-I/O timeouts
# plus one asyncio wall-clock deadline that a byte-dripping peer cannot
# outlive.
STT_CONNECT_TIMEOUT_SECONDS = 5.0
STT_TOTAL_TIMEOUT_SECONDS = 120.0
# One retry (VOICE_PLAN V-x, remediated 2026-09-29): a cold provider queue
# answering 429/503 once must not lose the patient's take. Honors
# Retry-After up to this ceiling, else a fixed backoff.
STT_RETRY_BACKOFF_SECONDS = 1.0
STT_RETRY_AFTER_CEILING_SECONDS = 5.0
STT_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
# A transcript of a five-minute journal is a few KiB. One MiB leaves room
# for provider envelope changes while preventing a compromised endpoint
# from making an API worker buffer an arbitrarily large response.
STT_MAX_RESPONSE_BYTES = 1 * 1024 * 1024
# Journal-sized bounds on everything the provider returns or that we
# forward to translation — a transcript is entry text, nothing more.
MAX_TRANSCRIPT_CHARS = 100_000
MAX_TRANSLATION_INPUT_CHARS = 100_000
MAX_TRANSLATION_OUTPUT_CHARS = 100_000

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Server-side mime allowlist and the extension each implies. Mirrored in
# shared/audio_vectors.json (pinned by tests on both sides); the client's
# filename is never trusted — the extension is derived from THIS table.
MIME_TO_EXTENSION: dict[str, str] = {
    "audio/webm": ".webm",
    "audio/mp4": ".m4a",
    "audio/m4a": ".m4a",
    "audio/x-m4a": ".m4a",
    "audio/ogg": ".ogg",
    "audio/mpeg": ".mp3",
    "audio/wav": ".wav",
}
ALLOWED_AUDIO_MIMES = frozenset(MIME_TO_EXTENSION)


def normalize_mime(raw: str) -> str:
    """Strip codec parameters ('audio/webm;codecs=opus' → 'audio/webm')."""
    return raw.split(";", 1)[0].strip().lower()


# Provider language strings → ISO 639-1. Whisper's verbose_json returns
# full names ("spanish"); gpt-4o-transcribe returns codes. Two-letter
# values pass through; unknown names leave language=None (callers fall
# back to English-translation analysis or the original text). Pinned by
# shared/audio_vectors.json.
LANGUAGE_NAME_TO_ISO: dict[str, str] = {
    "afrikaans": "af",
    "albanian": "sq",
    "amharic": "am",
    "arabic": "ar",
    "armenian": "hy",
    "azerbaijani": "az",
    "basque": "eu",
    "belarusian": "be",
    "bengali": "bn",
    "bosnian": "bs",
    "bulgarian": "bg",
    "catalan": "ca",
    "chinese": "zh",
    "croatian": "hr",
    "czech": "cs",
    "danish": "da",
    "dutch": "nl",
    "english": "en",
    "estonian": "et",
    "finnish": "fi",
    "french": "fr",
    "galician": "gl",
    "german": "de",
    "greek": "el",
    "gujarati": "gu",
    "hebrew": "he",
    "hindi": "hi",
    "hungarian": "hu",
    "icelandic": "is",
    "indonesian": "id",
    "italian": "it",
    "japanese": "ja",
    "javanese": "jv",
    "kannada": "kn",
    "kazakh": "kk",
    "khmer": "km",
    "korean": "ko",
    "lao": "lo",
    "latvian": "lv",
    "lithuanian": "lt",
    "macedonian": "mk",
    "malay": "ms",
    "malayalam": "ml",
    "maltese": "mt",
    "marathi": "mr",
    "myanmar": "my",
    "nepali": "ne",
    "norwegian": "no",
    "pashto": "ps",
    "persian": "fa",
    "polish": "pl",
    "portuguese": "pt",
    "punjabi": "pa",
    "romanian": "ro",
    "russian": "ru",
    "serbian": "sr",
    "sinhala": "si",
    "slovak": "sk",
    "slovenian": "sl",
    "somali": "so",
    "spanish": "es",
    "swahili": "sw",
    "swedish": "sv",
    "tagalog": "tl",
    "tajik": "tg",
    "tamil": "ta",
    "telugu": "te",
    "thai": "th",
    "turkish": "tr",
    "ukrainian": "uk",
    "urdu": "ur",
    "uzbek": "uz",
    "vietnamese": "vi",
    "welsh": "cy",
    "yiddish": "yi",
    "yoruba": "yo",
}


def normalize_language(raw: str) -> str | None:
    """Provider language string → ISO 639-1, or None when unrecognized."""
    value = raw.strip().lower()
    if not value:
        return None
    if len(value) == 2 and value.isalpha():
        return value
    return LANGUAGE_NAME_TO_ISO.get(value)


def processing_policy_fingerprint(settings: Settings) -> str | None:
    """Stable, non-secret identity of the configured STT policy.

    Same construction and rationale as llm.processing_policy_fingerprint:
    a boolean consent cannot survive an operator switching STT vendors,
    endpoints, models, or retention terms. Includes the disclosure
    version so re-worded consent copy invalidates persisted consent even
    when the operator forgets to bump MINDPATTERN_STT_POLICY_VERSION.
    """
    if not settings.stt_url.strip():
        return None
    policy = {
        "url": settings.stt_url.strip().rstrip("/"),
        "model": settings.stt_model,
        "provider": settings.stt_provider_name.strip(),
        "retention": settings.stt_data_retention.strip(),
        "version": settings.stt_policy_version.strip(),
        "disclosure": STT_DISCLOSURE_VERSION,
    }
    encoded = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def consent_is_current(user, settings: Settings) -> bool:
    """Whether this user has accepted the current STT policy exactly."""
    current = processing_policy_fingerprint(settings)
    return bool(current and user.voice_consent and user.voice_consent_policy == current)


@dataclass
class TranscriptionResult:
    text: str
    language_iso: str | None
    language_raw: str


def _clean_transcript(raw: object) -> str:
    """Provider output → bounded, control-free text ('' when absent)."""
    if not isinstance(raw, str):
        return ""
    text = _CONTROL_CHARS.sub(" ", raw).strip()
    return text[:MAX_TRANSCRIPT_CHARS]


class SpeechToText:
    """One bounded round-trip to an OpenAI-compatible transcription API."""

    name = "stt"

    def __init__(self, url: str, api_key: str, model: str = "whisper-1",
                 total_timeout_seconds: float = STT_TOTAL_TIMEOUT_SECONDS) -> None:
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.total_timeout_seconds = float(total_timeout_seconds)

    async def _post_audio(self, files: dict, data: dict) -> dict:
        """Stream a capped transcription response under a true deadline.

        The same guard set as LLMAnalyzer._post_async (see the module
        docstring there): per-I/O timeouts + one wall-clock budget,
        no redirects, no ambient proxies/CAs, content-length pre-check
        and decoded-byte cap so a deceptive or compressed response
        cannot exceed the contract.
        """
        import httpx  # imported lazily; keeps the dependency off the unit-test path

        timeout = httpx.Timeout(
            connect=STT_CONNECT_TIMEOUT_SECONDS,
            read=self.total_timeout_seconds,
            write=self.total_timeout_seconds,
            pool=self.total_timeout_seconds,
        )
        response_bytes = bytearray()
        async with asyncio.timeout(self.total_timeout_seconds):
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                async with client.stream(
                    "POST",
                    f"{self.url}/audio/transcriptions",
                    files=files,
                    data=data,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                ) as response:
                    response.raise_for_status()
                    content_length = response.headers.get("content-length")
                    if content_length is not None:
                        try:
                            declared_length = int(content_length)
                        except ValueError as exc:
                            raise ValueError("STT response has invalid Content-Length") from exc
                        if declared_length < 0 or declared_length > STT_MAX_RESPONSE_BYTES:
                            raise ValueError("STT response exceeds size limit")
                    async for chunk in response.aiter_bytes(chunk_size=64 * 1024):
                        if len(response_bytes) + len(chunk) > STT_MAX_RESPONSE_BYTES:
                            raise ValueError("STT response exceeds size limit")
                        response_bytes.extend(chunk)
        return json.loads(bytes(response_bytes))

    async def _post_audio_with_retry(self, files: dict, data: dict) -> dict:
        """One bounded retry on a transient upstream refusal (429/5xx).

        A second failure propagates — the route maps every upstream
        failure to one 502 outcome for the client either way.
        """
        import httpx  # lazy, mirrors _post_audio

        for attempt in (0, 1):
            try:
                return await self._post_audio(files, data)
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if attempt == 0 and status in STT_RETRYABLE_STATUS:
                    retry_after = exc.response.headers.get("retry-after")
                    try:
                        delay = min(float(retry_after), STT_RETRY_AFTER_CEILING_SECONDS)
                    except (TypeError, ValueError):
                        delay = 0.0
                    await asyncio.sleep(max(delay, STT_RETRY_BACKOFF_SECONDS))
                    continue
                raise

    async def transcribe(self, audio: bytes, mime: str) -> TranscriptionResult:
        """Transcribe in the spoken language; the provider detects it.

        ``whisper-1`` answers the detected language only under
        ``verbose_json``; the ``gpt-4o-transcribe`` family includes it in
        the plain ``json`` shape. Both shapes are accepted — only the
        ``text`` and ``language`` fields are read.
        """
        normalized = normalize_mime(mime)
        if normalized not in ALLOWED_AUDIO_MIMES:
            raise ValueError(f"unsupported audio mime {normalized!r}")
        extension = MIME_TO_EXTENSION[normalized]
        response_format = "json" if self.model.startswith("gpt-4o") else "verbose_json"
        body = await self._post_audio_with_retry(
            files={"file": (f"recording{extension}", audio, normalized)},
            data={"model": self.model, "response_format": response_format},
        )
        language_raw = str(body.get("language") or "").strip().lower()
        return TranscriptionResult(
            text=_clean_transcript(body.get("text")),
            language_iso=normalize_language(language_raw),
            language_raw=language_raw or "unknown",
        )


_TRANSLATE_SYSTEM_PROMPT = (
    "You are a translation engine for personal journal entries. Translate "
    "the user's text into plain, natural English. Preserve the original "
    "meaning and tone; do not summarize, embellish, answer, or comment. "
    "Return ONLY the translation as plain text."
)


async def translate_to_english(
    settings: Settings, text: str, source_lang: str | None
) -> str | None:
    """English translation of transcript text via the existing LLM client.

    Returns None (degraded mode) when the chat endpoint is unconfigured.
    Reuses LLMAnalyzer's bounded POST unchanged — the request is thread-
    offloaded because that seam is synchronous by design (the analysis
    worker contract); failures log and return None rather than failing
    the transcription, which stands on its own.
    """
    if not settings.llm_url.strip() or not text.strip():
        return None
    from .llm import LLMAnalyzer

    analyzer = LLMAnalyzer(settings.llm_url, settings.llm_api_key, settings.llm_model)
    bounded = text[:MAX_TRANSLATION_INPUT_CHARS]
    payload = {
        "model": settings.llm_model,
        "max_tokens": min(4096, max(512, len(bounded) // 2 + 256)),
        "temperature": 0.0,
        "messages": [
            {"role": "system", "content": _TRANSLATE_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": json.dumps(
                    {"source_language": source_lang or "auto", "text": bounded}
                ),
            },
        ],
    }
    try:
        body = await asyncio.to_thread(analyzer._post, payload)
        content = body["choices"][0]["message"]["content"]
    except Exception as exc:  # noqa: BLE001 — translation is a degraded-mode extra
        logger.warning(
            "transcript translation failed (%s); returning untranslated",
            type(exc).__name__,
        )
        return None
    return _clean_transcript(content)[:MAX_TRANSLATION_OUTPUT_CHARS] or None


def get_stt(settings: Settings) -> SpeechToText | None:
    """The configured transcription client, or None (feature off).

    Same standing as llm.get_enricher: an unset URL means the deployment
    has no STT path, and per-user consent cannot turn one on.
    """
    if settings.stt_url.strip():
        return SpeechToText(
            settings.stt_url,
            settings.stt_api_key,
            settings.stt_model,
            total_timeout_seconds=settings.stt_timeout_seconds,
        )
    return None


def translation_dispatch_allowed(user, settings: Settings) -> bool:
    """Whether THIS user's transcript may be handed to the LLM translation
    path (audit 2026-09-29, H4).

    Translation rides the chat-completions client, so it inherits the
    LLM consent surface: an endpoint configured but not consented-to for
    this account must not receive journal text through the voice path.
    An UNCONFIGURED endpoint returns True — translate_to_english itself
    degrades to None when llm_url is empty (nothing is dispatched), and
    the route needs to distinguish "nothing configured" from
    "configured but forbidden" only for the suppressed case.
    """
    if not settings.llm_url.strip():
        return True
    from .llm import consent_is_current

    return consent_is_current(user, settings)
