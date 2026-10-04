/**
 * Same-origin API client with an in-memory bearer token.
 *
 * The API origin is fixed: a configurable sign-in endpoint could choose a
 * salt and harvest password-derived verifiers. Production routes /api through
 * the app's HTTPS origin; development uses Vite's same-origin proxy.
 *
 * Requests omit cookies and referrers, reject redirects and foreign response
 * origins, bypass caches, and use session-scoped cancellation. A one-shot
 * 401/410 handler locks the session. Bulk operations have separate deadlines.
 */

import { currentOrigin } from "../platform";

const API_PREFIX = "/api/v1";

/** Request deadline: without one, a hung backend parks the UI forever on
 *  a fetch that will never answer. */
export const REQUEST_TIMEOUT_MS = 15_000;

/** Voice-call deadline (VOICE_PLAN 2026-09-29, audit H3): the server
 *  budgets 120 s for one upstream transcription (stt_timeout_seconds) and
 *  an attachment upload carries megabytes of base64 ciphertext — the 15 s
 *  global cap silently killed every long take after the mic had already
 *  done its work. 180 s = the server budget plus margin. Pinned >
 *  REQUEST_TIMEOUT_MS by tests so the regression cannot return quietly. */
export const VOICE_REQUEST_TIMEOUT_MS = 180_000;

/** Export deadline (2026-10-01 audit L-5): the streamed export walks the
 *  WHOLE account (up to the 256 MiB blob quota) — the 15 s global cap
 *  timed out large journals over slow links before the first byte of the
 *  download. 120 s mirrors the voice-class budget for a bulk read. */
export const EXPORT_REQUEST_TIMEOUT_MS = 120_000;

function isDevelopmentBuild(): boolean {
  return import.meta.env.DEV === true || import.meta.env.MODE === "test";
}

function isExplicitLoopback(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "[::1]" ||
    host === "::1"
  );
}

export function normalizeApiBaseUrl(candidate: string): string {
  const trimmed = candidate.trim().replace(/\/+$/, "");
  if (trimmed === "") return "";
  try {
    const url = new URL(trimmed);
    const permittedProtocol =
      url.protocol === "https:" ||
      (isDevelopmentBuild() &&
        url.protocol === "http:" &&
        isExplicitLoopback(url.hostname));
    // Credentials, query strings, and fragments do not belong in a stable
    // API base. A userinfo component is easy to misread in a login form
    // and has historically been used for URL spoofing.
    if (
      !permittedProtocol ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    )
      return "";
    return url.origin + url.pathname.replace(/\/+$/, "");
  } catch {
    return "";
  }
}

/** The one API base this client will ever use: the page's own origin. */
export function apiBaseUrl(): string {
  const normalized = normalizeApiBaseUrl(currentOrigin());
  if (!normalized) {
    throw new ApiError(
      0,
      "this app must be served over HTTPS (or a local development server)",
    );
  }
  return normalized;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public code?: string,
    public retryAfterMs?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** The backend error-code contract (docs/api.md), as the
 *  mobile client carries it. A code is attacker-controllable text like
 *  `detail`, but it feeds BRANCH logic, not dialogs: accept only the known
 *  slugs (anything else degrades to undefined, and the caller falls back
 *  to status/detail matching). */
export const API_ERROR_CODES = [
  "validation_error",
  "quota_exceeded",
  "blob_quota_exceeded",
  "verification_failed",
  "rate_limited",
  "payload_too_large",
  "not_found",
  "conflict",
  "collection_changed",
  "unauthorized",
  "invalid_credentials",
  "forbidden",
  "account_deleted",
  "gone",
  "method_not_allowed",
  "request_timeout",
  "version_conflict",
  "disclosure_outdated",
  "llm_unavailable",
  "feedback_blob_invalid",
  "rekey_key_mismatch",
  "processing_session_required",
  "processing_session_invalid",
  "step_up_required",
  "step_up_invalid",
  "entry_blob_invalid",
  "entry_payload_malformed",
  "totp_required",
  "totp_code_invalid",
  "key_scheme_conflict",
  "envelope_key_mismatch",
  // Voice journaling (VOICE_PLAN 2026-09-29).
  "voice_consent_required",
  "stt_unconfigured",
  "stt_unavailable",
  "stt_upstream",
  "audio_too_large",
  "audio_storage_unconfigured",
  "audio_storage_failed",
  "audio_quota_exceeded",
  "audio_expired",
  "unknown_entry",
  "consent_voice_share_required",
  "internal_error",
  "service_unavailable",
  "bad_request",
] as const;
export type ApiErrorCode = (typeof API_ERROR_CODES)[number];

function sanitizeCode(code: unknown): ApiErrorCode | undefined {
  return typeof code === "string" &&
    (API_ERROR_CODES as readonly string[]).includes(code)
    ? (code as ApiErrorCode)
    : undefined;
}

/** Retry-After on a 429 (or a 503 — the backend emits it there too) is
 *  seconds (or an HTTP-date); it is untrusted input — clamp to a sane
 *  ceiling so a hostile server cannot park the client for days. */
const MAX_RETRY_AFTER_MS = 60 * 60_000;
export function parseRetryAfter(header: string | null): number | undefined {
  if (!header) return undefined;
  const seconds = Number(header);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.min(seconds * 1000, MAX_RETRY_AFTER_MS);
  }
  const date = Date.parse(header);
  if (Number.isFinite(date)) {
    return Math.min(Math.max(0, date - Date.now()), MAX_RETRY_AFTER_MS);
  }
  return undefined;
}

interface Session {
  token: string;
  userId: string;
  username: string;
  baseUrl: string;
  /** Cancels all in-flight authenticated fetches at logout / expiry. */
  controller: AbortController;
}

let session: Session | null = null;

/** Proactive expiry guard (audit 2026-09-26 LOW): TokenResponse.expires_in
 *  used to be ignored — expiry was only discovered mid-write, as a 401 on
 *  whatever request happened to cross the deadline. The guard fires the
 *  SAME session-expiry funnel (App routes it to the sessionLock lockDown)
 *  slightly BEFORE the server would start refusing the token. */
const TOKEN_EXPIRY_GUARD_MARGIN_MS = 60_000;
/** setTimeout's delay ceiling (2^31-1 ms ≈ 24.8 days): anything larger
 *  overflows to "fire immediately". Real token lifetimes sit far below
 *  this, so the clamp is purely the overflow backstop. */
const TOKEN_EXPIRY_GUARD_MAX_MS = 2 ** 31 - 1;

let tokenExpiryTimer: ReturnType<typeof setTimeout> | null = null;

function clearTokenExpiryGuard(): void {
  if (tokenExpiryTimer !== null) {
    clearTimeout(tokenExpiryTimer);
    tokenExpiryTimer = null;
  }
}

function armTokenExpiryGuard(expiresInSeconds: number | undefined): void {
  clearTokenExpiryGuard();
  if (
    typeof expiresInSeconds !== "number" ||
    !Number.isFinite(expiresInSeconds) ||
    expiresInSeconds <= 0
  )
    return;
  const delay = Math.min(
    Math.max(expiresInSeconds * 1000 - TOKEN_EXPIRY_GUARD_MARGIN_MS, 0),
    TOKEN_EXPIRY_GUARD_MAX_MS,
  );
  tokenExpiryTimer = setTimeout(() => {
    tokenExpiryTimer = null;
    if (!session) return; // a replacement session already cleared this
    if (!sessionExpiredFired) {
      sessionExpiredFired = true;
      sessionExpiredHandler?.(
        new ApiError(401, "session token expired", "unauthorized"),
        {
          userId: session.userId,
          origin: session.baseUrl,
          accountDeleted: false,
        },
      );
    }
    clearSession();
    // No new timer here by contract: only setSession (a fresh acquisition)
    // arms the guard again — a locked session must not keep timers alive.
  }, delay);
}

export function setSession(
  token: string,
  userId: string,
  username: string,
  expiresInSeconds?: number,
): void {
  if (!token.trim()) throw new ApiError(0, "invalid empty session token");
  const baseUrl = apiBaseUrl();
  // A replacement session must not leave requests for the old account
  // alive in the background.
  clearSession();
  session = {
    token,
    userId,
    username,
    baseUrl,
    controller: new AbortController(),
  };
  // A new session re-arms the expiry latch: every sign-in gets its own
  // one-shot fire, even without a page reload in between.
  sessionExpiredFired = false;
  armTokenExpiryGuard(expiresInSeconds);
}

export function clearSession(): void {
  clearTokenExpiryGuard();
  session?.controller.abort();
  session = null;
}

export function hasSession(): boolean {
  return session !== null;
}

/** Async work beyond fetch can fence itself to the session that began it. */
export function sessionAbortSignal(): AbortSignal | null {
  return session?.controller.signal ?? null;
}

export function sessionUserId(): string | null {
  return session?.userId ?? null;
}

export function sessionUsername(): string | null {
  return session?.username ?? null;
}

function message(detail: unknown, status: number): string {
  return detailToMessage(detail, status);
}

/** Server-provided detail is attacker-controllable text (a hostile or
 * compromised server): cap length, strip URLs (ANY scheme — tel:,
 * custom-app schemes, not just http), scheme-less domains, phone-like
 * digit runs, and invisible/bidi characters so an error banner can never
 * be turned into a phishing surface. Ported byte-for-byte in behavior
 * from the mobile client's F2 sanitizer (parity fix W-2, audit
 * 2026-09-25); the corpus lives in tests/api.test.ts. */
const MAX_ERROR_MESSAGE_CHARS = 200;

export function sanitizeDetail(text: string): string {
  const stripped = text
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    // Bidi overrides / isolates and zero-width characters: invisible
    // homoglyph tricks that can flip or disguise error-dialog text.
    // U+2060-U+206F (word joiner, invisible math/operators) and U+FEFF
    // are in the strip set because the 2026-09-19 mobile audit smuggled a
    // word joiner INSIDE a domain ("bit\u2060.ly") so the domain rules
    // below never matched it. Invisibles go FIRST so the domain regexes
    // see the cleaned text.
    .replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g, "")
    .replace(/https?:\/\/\S+/gi, "")
    // Any other scheme://… (evilapp://pay, ftp://…) — same phishing class;
    // the scheme AND its payload go, like the http case above.
    .replace(/[a-z][a-z0-9+.-]*:\/\/\S+/gi, "")
    // Scheme-less domains ("go to evil.com/support") — ANY alpha TLD of
    // 2-24 chars, never an allowlist: the 2026-09-19 mobile audit walked
    // bit.ly / mindpattern-support.de / discord.gg straight through the
    // old com|net|org|… list. Over-stripping ("node.js" in a stack
    // trace) is the safe direction for attacker-controlled text.
    .replace(/\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b(?::\d+)?(?:\/\S*)?/gi, "")
    // Phone-like digit runs ("call 555-0134") — separators included.
    .replace(/\d[\d\s().-]{2,}\d/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return stripped.length > MAX_ERROR_MESSAGE_CHARS
    ? `${stripped.slice(0, MAX_ERROR_MESSAGE_CHARS)}…`
    : stripped;
}

/** Map a server error body's `detail` to banner copy. FastAPI validation
 * errors put a list of message objects there; both shapes sanitize.
 * Exported for tests: the sanitization is a security property. */
export function detailToMessage(detail: unknown, status: number): string {
  if (typeof detail === "string")
    return sanitizeDetail(detail) || `request failed (${status})`;
  if (Array.isArray(detail)) {
    const parts = detail.map((d) =>
      typeof d === "object" &&
      d !== null &&
      "msg" in d &&
      typeof (d as { msg: unknown }).msg === "string"
        ? (d as { msg: string }).msg
        : "invalid field",
    );
    if (parts.length > 0)
      return sanitizeDetail(parts.join("; ")) || `request failed (${status})`;
  }
  return `request failed (${status})`;
}

/** fetch with a deadline; a timeout surfaces as the same ApiError(0, …)
 * shape as an unreachable server. */
async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  expectedOrigin: string,
  sessionSignal?: AbortSignal,
  timeoutMs: number = REQUEST_TIMEOUT_MS,
): Promise<Response> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout>;
  const cleanup = (): void => {
    clearTimeout(timer);
    sessionSignal?.removeEventListener("abort", abortForSessionEnd);
  };
  const abortForSessionEnd = (): void => {
    controller.abort();
    cleanup();
  };
  timer = setTimeout(() => {
    controller.abort();
    cleanup();
  }, timeoutMs);
  if (sessionSignal?.aborted) controller.abort();
  else
    sessionSignal?.addEventListener("abort", abortForSessionEnd, {
      once: true,
    });
  try {
    let response = await fetch(url, {
      ...init,
      // Credentials are supplied only in Authorization, never ambient
      // cookies. Refusing redirects means a 30x cannot forward that bearer
      // token to another origin before this code gets to inspect it.
      credentials: "omit",
      redirect: "error",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      signal: controller.signal,
    });
    if (response.url) {
      try {
        if (new URL(response.url).origin !== new URL(expectedOrigin).origin) {
          throw new ApiError(
            0,
            "server redirected the request to a different origin",
          );
        }
      } catch (err) {
        if (err instanceof ApiError) throw err;
        throw new ApiError(0, "server returned an invalid response origin");
      }
    }
    // A 204 is complete even when a proxy/alternate fetch exposes an empty
    // stream. Constructing Response with that status and a body is forbidden.
    if (response.status === 204) {
      void response.body?.cancel().catch(() => undefined);
      cleanup();
      return response;
    }
    if (response instanceof Response && response.body)
      response = guardResponseStream(
        response,
        controller,
        cleanup,
        timeoutMs === EXPORT_REQUEST_TIMEOUT_MS
          ? 100 * 1024 * 1024
          : 16 * 1024 * 1024,
      );
    for (const method of [
      "text",
      "json",
      "arrayBuffer",
      "blob",
      "formData",
    ] as const) {
      const original = response[method]?.bind(response);
      if (!original) continue;
      Object.defineProperty(response, method, {
        configurable: true,
        value: async () => {
          try {
            // Race consumption against abort even for alternate fetch implementations that ignore its signal.
            const value = await new Promise<unknown>((resolve, reject) => {
              const onAbort = (): void =>
                reject(
                  new ApiError(
                    0,
                    sessionSignal?.aborted
                      ? "session ended"
                      : "request timed out while reading response",
                  ),
                );
              if (controller.signal.aborted) {
                onAbort();
                return;
              }
              controller.signal.addEventListener("abort", onAbort, {
                once: true,
              });
              Promise.resolve(original())
                .then(resolve, reject)
                .finally(() =>
                  controller.signal.removeEventListener("abort", onAbort),
                );
            });
            if (controller.signal.aborted)
              throw new ApiError(0, "session ended or response timed out");
            return value;
          } finally {
            cleanup();
          }
        },
      });
    }
    if (response.status === 204 || response.body === null) {
      // Mocks may omit body while still implementing json/text. Native empty bodies need no deadline.
      if (response instanceof Response && response.body === null) cleanup();
    }
    return response;
  } catch (err) {
    cleanup();
    if (err instanceof ApiError) throw err;
    if (err instanceof Error && err.name === "AbortError") {
      if (sessionSignal?.aborted) throw new ApiError(0, "session ended");
      throw new ApiError(0, `request timed out after ${timeoutMs / 1000}s`);
    }
    throw err;
  }
}

/** Session-expiry hook: any 401 (or 410 account death) fires this ONCE per
 *  session (setSession re-arms it) — App funnels the whole UI to an
 *  explicit sign-in state instead of a cryptic banner while keys sit in
 *  memory. The error is handed over so the lock screen can say WHAT
 *  happened (expired vs rotated vs deleted — WEB_PLAN D-8). */
export interface SessionDeathContext {
  userId: string;
  origin: string;
  accountDeleted: boolean;
}
let sessionExpiredHandler:
  ((err: ApiError, context: SessionDeathContext) => void) | null = null;
let sessionExpiredFired = false;
export function setSessionExpiredHandler(
  fn: ((err: ApiError, context: SessionDeathContext) => void) | null,
): void {
  sessionExpiredHandler = fn;
  sessionExpiredFired = false;
}

interface ApiResponse<T> {
  data: T;
  headers: Headers;
}

function isSessionDeath(
  status: number,
  code: ApiErrorCode | undefined,
  path: string,
): boolean {
  if (status === 401) return true;
  // `gone` is the backend's legacy/default 410 and is not globally proof of
  // account death. Keep compatibility only on the explicit account-delete
  // lifecycle route; arbitrary expired resources must never erase a vault.
  return (
    status === 410 &&
    (code === "account_deleted" || (code === "gone" && path === "/account"))
  );
}

async function requestWithResponse<T>(
  method: string,
  path: string,
  body?: unknown,
  extraHeaders: Record<string, string> = {},
  timeoutMs: number = REQUEST_TIMEOUT_MS,
): Promise<ApiResponse<T>> {
  const activeSession = session;
  if (!activeSession) throw new ApiError(0, "not signed in");
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${activeSession.token}`,
    ...extraHeaders,
  };
  let response: Response;
  try {
    response = await fetchWithTimeout(
      `${activeSession.baseUrl}${API_PREFIX}${path}`,
      {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      },
      activeSession.baseUrl,
      activeSession.controller.signal,
      timeoutMs,
    );
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(0, "server unreachable — check your connection");
  }
  // A fetch implementation can resolve despite an abort race. Do not parse
  // or return protected content once logout / expiry has replaced the
  // session that initiated this request.
  if (session !== activeSession) throw new ApiError(0, "session ended");
  const raw = response.status === 204 ? "{}" : await response.text();
  if (session !== activeSession) throw new ApiError(0, "session ended");
  const data = safeJson(raw) as { detail?: unknown; code?: unknown };
  const code = sanitizeCode(data.code);
  const accountDeleted =
    response.status === 410 && isSessionDeath(response.status, code, path);
  if (isSessionDeath(response.status, code, path) && !sessionExpiredFired) {
    sessionExpiredFired = true;
    sessionExpiredHandler?.(
      new ApiError(
        response.status,
        message(data.detail, response.status),
        code,
      ),
      {
        userId: activeSession.userId,
        origin: activeSession.baseUrl,
        accountDeleted,
      },
    );
  }
  if (response.status === 204)
    return { data: null as T, headers: response.headers };
  if (!response.ok) {
    throw new ApiError(
      response.status,
      message(data.detail, response.status),
      sanitizeCode(data.code),
      response.status === 429 || response.status === 503
        ? parseRetryAfter(response.headers.get("Retry-After"))
        : undefined,
    );
  }
  return { data: data as T, headers: response.headers };
}

function safeJson(raw: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (typeof parsed === "object" && parsed !== null)
      return parsed as Record<string, unknown>;
    return {};
  } catch {
    return {};
  }
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  extraHeaders: Record<string, string> = {},
  timeoutMs: number = REQUEST_TIMEOUT_MS,
): Promise<T> {
  return (
    await requestWithResponse<T>(method, path, body, extraHeaders, timeoutMs)
  ).data;
}

// --- unauthenticated auth flow (uses the same request core, no token) ------

async function authRequest<T>(
  method: string,
  path: string,
  body?: unknown,
  extraHeaders: Record<string, string> = {},
): Promise<T> {
  const baseUrl = apiBaseUrl();
  let response: Response;
  try {
    response = await fetchWithTimeout(
      `${baseUrl}${API_PREFIX}${path}`,
      {
        method,
        headers: { "Content-Type": "application/json", ...extraHeaders },
        body: body === undefined ? undefined : JSON.stringify(body),
      },
      baseUrl,
    );
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(0, "server unreachable — check your connection");
  }
  const data = (await response.json().catch(() => ({}))) as {
    detail?: unknown;
    code?: unknown;
  };
  if (!response.ok) {
    throw new ApiError(
      response.status,
      message(data.detail, response.status),
      sanitizeCode(data.code),
      response.status === 429 || response.status === 503
        ? parseRetryAfter(response.headers.get("Retry-After"))
        : undefined,
    );
  }
  return data as T;
}

// --- auth + meta -------------------------------------------------------------

export interface TokenResponse {
  token: string;
  user_id: string;
  expires_in: number;
  role: string;
  /** The account's key scheme since the 2026-09-26 wave ("v1" | "v2").
   *  OPTIONAL and ignored-when-absent: an older backend omits it, and the
   *  unlock flow treats absent as v1 (the only scheme such a backend has).
   *  Unknown future values never open a new path — anything other than
   *  "v2" keeps the v1 derivation. */
  key_scheme?: string;
}

export interface ServerMeta {
  version: string;
  api_version: string;
  unlock_days: number;
  llm_available: boolean;
  llm_provider_name: string | null;
  llm_data_retention: string | null;
  llm_policy_fingerprint?: string | null;
  sharing_available: boolean;
  sharing_disclosure_version: string;
  /** Voice journaling (2026-09-29): additive; older backends omit them and
   *  the mic button treats absence as unavailable. */
  audio_available?: boolean;
  stt_provider_name?: string | null;
  stt_data_retention?: string | null;
  stt_policy_fingerprint?: string | null;
}

/** POST /audio/transcriptions (VOICE_PLAN 2026-09-29). */
export interface AudioTranscriptionResponse {
  original_text: string;
  language: string | null;
  language_raw: string;
  english_text: string | null;
  provider_name: string;
  policy_version: string;
}

/** GET /audio/attachments/{id} — encrypted blob + playback metadata. */
export interface AudioAttachmentOut {
  id: string;
  client_entry_id: string;
  blob: string;
  mime_type: string;
  duration_seconds: number;
  size_bytes: number;
  created_at: string;
  expires_at: string;
}

/** GET/PUT /account/voice-consent. */
export interface VoiceConsentState {
  enabled: boolean;
  active_for_current_policy: boolean;
  voice_consent_at: string | null;
  voice_consent_disclosure: string | null;
  voice_consent_policy: string | null;
}

/** GET/PUT /account/llm-consent. A historic `enabled` choice is not an
 * active authorization once its disclosure or provider policy changes. */
export interface LlmConsentState {
  enabled: boolean;
  active_for_current_policy: boolean;
  llm_consent_at: string | null;
  llm_consent_disclosure: string | null;
  llm_consent_policy: string | null;
}

/** GET /auth/key-envelope (bearer): the v2 unlock material. v1 accounts
 *  answer key_scheme "v1" with null envelope fields. */
export interface KeyEnvelopeResponse {
  key_scheme: string;
  salt: string;
  kdf_params: unknown;
  wrapped_data_key: string | null;
}

/** The v2 registration envelope fields (both or neither — the backend
 *  rejects a half pair with 422). */
export interface RegistrationEnvelope {
  kdfParams: Record<string, unknown>;
  wrappedDataKeyB64: string;
}

export const MINIMUM_AGE_ATTESTATION = "minimum_age_confirmed_v1" as const;
export type MinimumAgeAttestation = typeof MINIMUM_AGE_ATTESTATION;

export const auth = {
  meta: () => authRequest<ServerMeta>("GET", "/meta"),
  saltFor: (username: string) =>
    authRequest<{ salt: string }>("POST", "/auth/salt", { username }),
  login: (username: string, verifierB64: string) =>
    authRequest<TokenResponse>("POST", "/auth/login", {
      username,
      verifier: verifierB64,
    }),
  register: (
    username: string,
    saltB64: string,
    verifierB64: string,
    ageAttestation: MinimumAgeAttestation,
    envelope?: RegistrationEnvelope,
  ) =>
    authRequest<TokenResponse>(
      "POST",
      "/auth/register",
      envelope === undefined
        ? {
            username,
            salt: saltB64,
            verifier: verifierB64,
            age_attestation: ageAttestation,
          }
        : {
            username,
            salt: saltB64,
            verifier: verifierB64,
            age_attestation: ageAttestation,
            kdf_params: envelope.kdfParams,
            wrapped_data_key: envelope.wrappedDataKeyB64,
          },
    ),
};

// --- entries -------------------------------------------------------------------

const ENTRY_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

export interface ListedEntry {
  id: string;
  client_entry_id: string;
  blob: string;
  entry_date: string;
  received_at: string;
  content_version?: number;
  /** Unexpired kept-recording metadata (VOICE_PLAN 2026-09-29); absent on
   *  entries without audio and on pre-voice backends. */
  audio?: { attachment_id: string; expires_at: string } | null;
}

/** The backend caps one page at 500 rows and 2 MiB of raw ciphertext. */
export const ENTRY_PAGE_LIMIT = 500;
export const ENTRY_PAGE_BYTES = 2 * 1024 * 1024;
export const ENTRY_LIST_PAGE_SIZE = 100;

export type EntriesRevision = string;

export interface ListedEntriesPage {
  entries: ListedEntry[];
  /** Absent means this filtered result set is complete. */
  nextOffset: number | null;
  /** Undefined when the connected backend predates snapshot pagination. */
  revision?: EntriesRevision;
}

export interface ListEntriesPageOptions {
  since?: string;
  limit?: number;
  offset?: number;
  pageBytes?: number;
  expectedRevision?: EntriesRevision;
}

/** A mid-walk 409 collection_changed is retryable from page one (the
 *  server tells us the snapshot moved). Two restarts cover a concurrent
 *  write; a third failure is an honest error, not a silent mixed history. */
export const MAX_LIST_SNAPSHOT_RESTARTS = 2;
/** The bounded-sync walk cap (mobile contract): a hostile server that
 *  keeps returning continuations must not keep the app paging forever. */
export const MAX_LIST_PAGES = 200;

/** Walk every byte-bounded page under one revision snapshot (mobile's
 *  listEntries contract): page one establishes the snapshot; every
 *  continuation sends it back so a concurrent write answers a retryable
 *  409 instead of causing offset drift. A headerless legacy server
 *  (no revision) walks unpinned with dedupe — never mixed. */
export async function listEntriesWalk(since?: string): Promise<ListedEntry[]> {
  for (let attempt = 0; attempt <= MAX_LIST_SNAPSHOT_RESTARTS; attempt += 1) {
    try {
      const all: ListedEntry[] = [];
      const seen = new Set<string>();
      const pageSize = ENTRY_PAGE_LIMIT;
      let offset = 0;
      let revision: EntriesRevision | null = null;
      let revisionMode: "unknown" | "snapshot" | "legacy" = "unknown";
      const getPage = async (
        pageOffset: number,
      ): Promise<ListedEntriesPage> => {
        const result = await api.listEntriesPage({
          since,
          limit: pageSize,
          offset: pageOffset,
          pageBytes: ENTRY_PAGE_BYTES,
          ...(revisionMode === "snapshot" && revision !== null
            ? { expectedRevision: revision }
            : {}),
        });
        const receivedRevision = result.revision ?? null;
        if (revisionMode === "unknown") {
          revisionMode = receivedRevision === null ? "legacy" : "snapshot";
          revision = receivedRevision;
        } else if (
          (revisionMode === "snapshot" && receivedRevision !== revision) ||
          (revisionMode === "legacy" && receivedRevision !== null)
        ) {
          // A load-balanced deployment changed protocol modes during one
          // walk. Restart instead of mixing unpinned and pinned pages.
          throw new ApiError(
            409,
            "the entries snapshot changed mid-walk — restarting",
            "collection_changed",
          );
        }
        return result;
      };
      for (let page = 0; page < MAX_LIST_PAGES; page += 1) {
        const result = await getPage(offset);
        for (const entry of result.entries) {
          if (seen.has(entry.client_entry_id)) continue; // legacy page-boundary drift
          seen.add(entry.client_entry_id);
          all.push(entry);
        }
        if (result.nextOffset === null) return all;
        offset = result.nextOffset;
      }
      const probe = await getPage(offset);
      if (probe.entries.length === 0 && probe.nextOffset === null) return all;
      throw new ApiError(
        0,
        "server keeps returning entry continuations — aborting sync",
      );
    } catch (err) {
      if (
        err instanceof ApiError &&
        err.status === 409 &&
        attempt < MAX_LIST_SNAPSHOT_RESTARTS
      )
        continue;
      throw err;
    }
  }
  throw new ApiError(0, "the entries collection kept changing — try again");
}

/** Decimal-only parsing avoids Number("1e3"), signs, whitespace, and
 *  precision loss quietly changing pagination state. */
function validatedNextOffset(
  header: string | null,
  offset: number,
  rowCount: number,
  resource: string,
): number | null {
  if (header === null) {
    // The backend sets X-Next-Offset only when more rows exist (entries.py):
    // an absent header on a page_bytes opt-in means THIS RESULT SET IS
    // COMPLETE — the documented terminal contract, never an error.
    return null;
  }
  if (!/^(?:0|[1-9][0-9]*)$/.test(header)) {
    throw new ApiError(
      0,
      `server returned an invalid ${resource} continuation`,
    );
  }
  const nextOffset = Number(header);
  // Offset pagination must advance exactly past the materialized rows —
  // this catches a malformed/proxy-injected cursor before it can loop or
  // skip rows, including "more after an empty page".
  if (
    !Number.isSafeInteger(nextOffset) ||
    rowCount === 0 ||
    nextOffset !== offset + rowCount
  ) {
    throw new ApiError(
      0,
      `server returned an invalid ${resource} continuation`,
    );
  }
  return nextOffset;
}

/** The server's snapshot counter is a signed 64-bit integer. Keep it as its
 *  canonical decimal wire representation: a JavaScript number would lose
 *  the low bits for most valid server values. */
const MAX_SIGNED_64_REVISION = "9223372036854775807";

function isCanonicalRevision(revision: string): boolean {
  return (
    /^(?:0|[1-9][0-9]{0,18})$/.test(revision) &&
    (revision.length < MAX_SIGNED_64_REVISION.length ||
      (revision.length === MAX_SIGNED_64_REVISION.length &&
        revision <= MAX_SIGNED_64_REVISION))
  );
}

function validatedRevision(
  header: string | null,
  expectedRevision: string | undefined,
  resource: string,
): string | undefined {
  if (header === null) {
    if (expectedRevision !== undefined) {
      throw new ApiError(0, `server dropped the ${resource} snapshot revision`);
    }
    return undefined;
  }
  if (!isCanonicalRevision(header)) {
    throw new ApiError(
      0,
      `server returned an invalid ${resource} snapshot revision`,
    );
  }
  if (expectedRevision !== undefined && header !== expectedRevision) {
    throw new ApiError(
      0,
      `server returned a changed ${resource} snapshot revision`,
    );
  }
  return header;
}

// --- measures -------------------------------------------------------------------

export interface ListedMeasure {
  id: string;
  client_measure_id: string;
  blob: string;
  measure_date: string;
  received_at: string;
}

export interface ListedMeasuresPage {
  measures: ListedMeasure[];
  nextOffset: number | null;
  revision?: string;
}

// --- sharing ---------------------------------------------------------------------

/** Keep in sync with backend/app/api/consents.py SHARING_DISCLOSURE_VERSION. */
export const SHARING_DISCLOSURE_VERSION = "v3";

export type StepUpAction =
  | "account_delete"
  | "llm_consent"
  | "voice_consent"
  | "sharing_grant"
  | "sharing_revoke"
  | "sharing_rewrap"
  | "sharing_voice";
const CONSENT_ID_PATTERN = /^[0-9a-f]{32}$/;

export interface ListedConsent {
  id: string;
  therapist_id: string;
  display_name: string;
  username: string;
  status: string;
  granted_at: string;
  revoked_at: string | null;
  /** The therapist's public wrap key (rotation flow): a client re-wrapping
   *  after a rekey needs the CURRENT key, which may have rotated since the
   *  grant. */
  therapist_wrap_pub_key?: string;
  /** Voice-sharing grant (VOICE_PLAN 2026-09-29): default false; additive
   *  for older backends. */
  share_voice?: boolean;
}

/** Relationship history is retained after revocation, so the active grants a
 * patient needs for rendering and key re-wrapping can sit beyond the first
 * 200 rows. Keep this in lockstep with the backend's public page cap. */
export const CONSENT_LIST_PAGE_SIZE = 200;
/** The backend retains at most 1,000 relationship rows per account. The sixth
 * request is the one harmless terminal probe needed by a headerless legacy
 * server whose retained count is an exact multiple of the page size. */
export const MAX_CONSENT_LIST_PAGES = 6;

export interface ListedConsentsPage {
  consents: ListedConsent[];
  nextOffset: number | null;
  /** Undefined only for a pre-snapshot server. */
  revision?: string;
}

function consentsRevisionConflict(): ApiError {
  return new ApiError(
    409,
    "consents changed while paging; retry the request",
    "collection_changed",
  );
}

/** Fetch every retained relationship under one collection revision. This is
 * deliberately the implementation behind api.listConsents so UI and re-key
 * callers cannot accidentally regress to treating page one as complete. */
export async function listConsentsWalk(): Promise<ListedConsent[]> {
  for (let attempt = 0; attempt <= MAX_LIST_SNAPSHOT_RESTARTS; attempt += 1) {
    try {
      const all: ListedConsent[] = [];
      const seen = new Set<string>();
      let offset = 0;
      let revision: string | null = null;
      let revisionMode: "unknown" | "snapshot" | "legacy" = "unknown";

      for (let page = 0; page < MAX_CONSENT_LIST_PAGES; page += 1) {
        const result = await api.listConsentsPage({
          offset,
          ...(revisionMode === "snapshot" && revision !== null
            ? { expectedRevision: revision }
            : {}),
        });
        const receivedRevision = result.revision ?? null;
        if (revisionMode === "unknown") {
          revisionMode = receivedRevision === null ? "legacy" : "snapshot";
          revision = receivedRevision;
        } else if (
          (revisionMode === "snapshot" && receivedRevision !== revision) ||
          (revisionMode === "legacy" && receivedRevision !== null)
        ) {
          throw consentsRevisionConflict();
        }

        for (const consent of result.consents) {
          if (seen.has(consent.id)) continue;
          seen.add(consent.id);
          all.push(consent);
        }
        if (result.nextOffset === null) return all;
        offset = result.nextOffset;
      }
      throw new ApiError(
        0,
        "server keeps returning consent continuations — aborting the request",
      );
    } catch (err) {
      if (
        err instanceof ApiError &&
        err.status === 409 &&
        err.code === "collection_changed" &&
        attempt < MAX_LIST_SNAPSHOT_RESTARTS
      ) {
        continue;
      }
      throw err;
    }
  }
  throw new ApiError(0, "could not obtain a stable consent snapshot");
}

export interface PairingLookup {
  therapist_id: string;
  display_name: string;
  wrap_pub_key: string;
  /** SAS out-of-band verification (2026-09-26): the 6-digit "123 456"
   *  string both pairing screens derive for this live session, and the
   *  wrap key's coarse 16-hex fingerprint. OPTIONAL: a backend predating
   *  the wave omits them and the Share view simply hides the comparison
   *  block (the deeper local key-fingerprint check stays). */
  sas?: string;
  wrap_key_fingerprint?: string;
}

// --- the authenticated endpoint surface -------------------------------------------

export const api = {
  meta: () => request<ServerMeta>("GET", "/meta"),
  /** The v2 unlock material (see KeyEnvelopeResponse). Called between
   *  login and vault adoption for key_scheme "v2" accounts only — v1
   *  accounts keep deriving locally and never pay this round trip. */
  keyEnvelope: () => request<KeyEnvelopeResponse>("GET", "/auth/key-envelope"),

  // --- voice journaling (VOICE_PLAN 2026-09-29) ---------------------------

  /** Transcribe one recording: the server returns the transcript in the
   *  spoken language, the detected language, and (when the translation LLM
   *  is configured) an English translation of the text. Audio bytes exist
   *  server-side only for the upstream call — never stored. */
  transcribeAudio: (audioB64: string, mime: string, durationSeconds: number) =>
    request<AudioTranscriptionResponse>(
      "POST",
      "/audio/transcriptions",
      {
        audio_b64: audioB64,
        mime,
        duration_seconds: durationSeconds,
      },
      {},
      VOICE_REQUEST_TIMEOUT_MS,
    ),

  /** Re-translate an EDITED transcript before saving (payload v3 keeps
   *  english_text in sync with the saved text). */
  translateText: (text: string, sourceLang: string | null) =>
    request<{ english_text: string | null }>("POST", "/audio/translations", {
      text,
      ...(sourceLang ? { source_lang: sourceLang } : {}),
    }),

  /** Store (or replace) the kept recording for one entry. The blob is the
   *  client-side AES-GCM envelope — opaque to the server. */
  uploadAudioAttachment: (
    clientEntryId: string,
    blobB64: string,
    mime: string,
    durationSeconds: number,
  ) => {
    if (!ENTRY_ID_PATTERN.test(clientEntryId))
      throw new ApiError(0, "invalid entry id — refusing the request");
    return request<{
      attachment_id: string;
      expires_at: string;
      size_bytes: number;
    }>(
      "POST",
      "/audio/attachments",
      {
        client_entry_id: clientEntryId,
        blob: blobB64,
        mime,
        duration_seconds: durationSeconds,
      },
      {},
      VOICE_REQUEST_TIMEOUT_MS,
    );
  },

  /** Fetch one kept recording (owner-only) for playback. */
  fetchAudioAttachment: (attachmentId: string) =>
    request<AudioAttachmentOut>(
      "GET",
      `/audio/attachments/${encodeURIComponent(attachmentId)}`,
    ),

  /** Delete the recording; the entry survives. */
  deleteAudioAttachment: (attachmentId: string) =>
    request<null>(
      "DELETE",
      `/audio/attachments/${encodeURIComponent(attachmentId)}`,
    ),

  /** Voice-consent record (the client toggle reads/writes this). */
  getVoiceConsent: () =>
    request<VoiceConsentState>("GET", "/account/voice-consent"),
  setVoiceConsent: (enabled: boolean, stepUpProof: string) =>
    request<VoiceConsentState>(
      "PUT",
      "/account/voice-consent",
      {
        enabled,
      },
      { "X-Step-Up-Proof": stepUpProof },
    ),

  /** Share-voice grant toggle on one therapist consent. */
  setShareVoice: (consentId: string, enabled: boolean, stepUpProof: string) =>
    request<{ id: string; share_voice: boolean }>(
      "PUT",
      `/consents/${encodeURIComponent(consentId)}/share-voice`,
      { enabled },
      { "X-Step-Up-Proof": stepUpProof },
    ),
  /** Logout deliberately does NOT ride the session's AbortController: the
   *  button fires this and then synchronously calls clearSession(), whose
   *  abort would cancel the very revocation the request exists to perform.
   *  Per-device since the 2026-09-26 wave: the server records this
   *  bearer's jti and only THIS token dies — other signed-in devices stay
   *  live (a legacy jti-less bearer still falls back to the account-wide
   *  epoch bump server-side). It keeps every other hardening (deadline,
   *  no credentials, redirect refusal, origin recheck) and uses the token
   *  captured at call time. */
  logout: async (): Promise<null> => {
    const activeSession = session;
    if (!activeSession) throw new ApiError(0, "not signed in");
    const response = await fetchWithTimeout(
      `${activeSession.baseUrl}${API_PREFIX}/auth/logout`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${activeSession.token}`,
        },
      },
      activeSession.baseUrl,
    );
    if (response.status === 204) return null;
    const data = (await response.json().catch(() => ({}))) as {
      detail?: unknown;
      code?: unknown;
    };
    if (!response.ok) {
      throw new ApiError(
        response.status,
        message(data.detail, response.status),
        sanitizeCode(data.code),
      );
    }
    return null;
  },

  createEntry: (
    clientEntryId: string,
    blobB64: string,
    entryDate: string,
    contentVersion?: number,
  ) => {
    if (!ENTRY_ID_PATTERN.test(clientEntryId))
      throw new ApiError(0, "invalid entry id — refusing the request");
    return request<{ id: string }>("POST", "/entries", {
      client_entry_id: clientEntryId,
      blob: blobB64,
      entry_date: entryDate,
      ...(contentVersion !== undefined
        ? { content_version: contentVersion }
        : {}),
    });
  },
  getEntry: (clientEntryId: string) => {
    if (!ENTRY_ID_PATTERN.test(clientEntryId))
      throw new ApiError(0, "invalid entry id — refusing the request");
    return request<ListedEntry>(
      "GET",
      `/entries/${encodeURIComponent(clientEntryId)}`,
    );
  },
  updateEntry: (
    clientEntryId: string,
    blobB64: string,
    entryDate: string,
    contentVersion?: number,
  ) => {
    if (!ENTRY_ID_PATTERN.test(clientEntryId))
      throw new ApiError(0, "invalid entry id — refusing the request");
    return request<{ id: string }>(
      "PUT",
      `/entries/${encodeURIComponent(clientEntryId)}`,
      {
        blob: blobB64,
        entry_date: entryDate,
        ...(contentVersion !== undefined
          ? { content_version: contentVersion }
          : {}),
      },
    );
  },
  deleteEntry: (clientEntryId: string) => {
    if (!ENTRY_ID_PATTERN.test(clientEntryId))
      throw new ApiError(0, "invalid entry id — refusing the request");
    return request<null>(
      "DELETE",
      `/entries/${encodeURIComponent(clientEntryId)}`,
    );
  },
  listEntriesPage: async (
    options: ListEntriesPageOptions = {},
  ): Promise<ListedEntriesPage> => {
    const limit = options.limit ?? ENTRY_LIST_PAGE_SIZE;
    const offset = options.offset ?? 0;
    const pageBytes = options.pageBytes ?? ENTRY_PAGE_BYTES;
    if (
      !Number.isInteger(limit) ||
      limit < 1 ||
      limit > ENTRY_PAGE_LIMIT ||
      !Number.isSafeInteger(offset) ||
      offset < 0 ||
      !Number.isInteger(pageBytes) ||
      pageBytes < 1 ||
      pageBytes > ENTRY_PAGE_BYTES ||
      (options.expectedRevision !== undefined &&
        !isCanonicalRevision(options.expectedRevision))
    ) {
      throw new ApiError(
        0,
        "invalid entry page request — refusing the request",
      );
    }
    const params = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
      page_bytes: String(pageBytes),
    });
    if (options.since) params.set("since", options.since);
    if (options.expectedRevision !== undefined)
      params.set("expected_revision", options.expectedRevision);
    const response = await requestWithResponse<ListedEntry[]>(
      "GET",
      `/entries?${params.toString()}`,
    );
    if (!Array.isArray(response.data))
      throw new ApiError(0, "server returned an invalid entries page");
    return {
      entries: response.data,
      nextOffset: validatedNextOffset(
        response.headers.get("X-Next-Offset"),
        offset,
        response.data.length,
        "entries",
      ),
      revision: validatedRevision(
        response.headers.get("X-Entries-Revision"),
        options.expectedRevision,
        "entries",
      ),
    };
  },

  createMeasure: (
    clientMeasureId: string,
    blobB64: string,
    measureDate: string,
  ) =>
    request<{ id: string }>("POST", "/measures", {
      client_measure_id: clientMeasureId,
      blob: blobB64,
      measure_date: measureDate,
    }),
  listMeasuresPage: async (
    params: { offset?: number; expectedRevision?: string } = {},
  ): Promise<ListedMeasuresPage> => {
    const offset = params.offset ?? 0;
    if (!Number.isSafeInteger(offset) || offset < 0)
      throw new ApiError(0, "invalid measure page request");
    if (
      params.expectedRevision !== undefined &&
      !isCanonicalRevision(params.expectedRevision)
    ) {
      throw new ApiError(0, "invalid measure page request");
    }
    const search = new URLSearchParams({
      limit: "100",
      page_bytes: String(ENTRY_PAGE_BYTES),
    });
    if (offset > 0) search.set("offset", String(offset));
    if (params.expectedRevision !== undefined)
      search.set("expected_revision", params.expectedRevision);
    const response = await requestWithResponse<ListedMeasure[]>(
      "GET",
      `/measures?${search.toString()}`,
    );
    if (!Array.isArray(response.data))
      throw new ApiError(0, "server returned an invalid measures page");
    return {
      measures: response.data,
      nextOffset: validatedNextOffset(
        response.headers.get("X-Next-Offset"),
        offset,
        response.data.length,
        "measures",
      ),
      revision: validatedRevision(
        response.headers.get("X-Measures-Revision"),
        params.expectedRevision,
        "measures",
      ),
    };
  },

  openProcessingSession: (dataKeyB64: string) =>
    request<{ session_token: string; expires_in: number }>(
      "POST",
      "/processing/sessions",
      { data_key: dataKeyB64 },
    ),
  recompute: (processingToken: string, feedbackBlob?: string) =>
    request<{
      phase: string;
      active_days?: number;
      streak?: number;
      days_remaining?: number;
    }>(
      "POST",
      "/insights/recompute",
      feedbackBlob
        ? ({ feedback_blob: feedbackBlob } as Record<string, unknown>)
        : undefined,
      { "X-Processing-Token": processingToken },
    ),
  insights: () =>
    request<{
      phase: string;
      active_days: number;
      streak: number;
      days_remaining: number;
      blob: string | null;
      state_seq?: number;
    }>("GET", "/insights"),
  questionToday: () =>
    request<{ for_date: string; blob: string }>("GET", "/questions/today"),

  /** The streamed ciphertext export — returns the RAW response (P7 turns it
   *  into a download); nothing about the request core is bypassed. */
  exportAccountRaw: async (): Promise<Response> => {
    const activeSession = session;
    if (!activeSession) throw new ApiError(0, "not signed in");
    // 2026-10-01 audit L-5: the export gets the bulk-read deadline (the
    // 15 s global cap killed large journals on slow links), and a 401
    // fires the same one-shot session-expiry latch every gated request
    // uses — the app used to keep a dead session until the next call.
    try {
      const response = await fetchWithTimeout(
        `${activeSession.baseUrl}${API_PREFIX}/account/export`,
        {
          method: "GET",
          headers: { Authorization: `Bearer ${activeSession.token}` },
          credentials: "omit",
        },
        activeSession.baseUrl,
        activeSession.controller.signal,
        EXPORT_REQUEST_TIMEOUT_MS,
      );
      if (session !== activeSession) throw new ApiError(0, "session ended");
      if (response.status === 401) {
        const err = new ApiError(401, "session ended", "unauthorized");
        if (!sessionExpiredFired) {
          sessionExpiredFired = true;
          sessionExpiredHandler?.(err, {
            userId: activeSession.userId,
            origin: activeSession.baseUrl,
            accountDeleted: false,
          });
        }
        void response.body?.cancel().catch(() => undefined);
        throw err;
      }
      if (response.status === 410) {
        const raw = await response.text();
        const body = safeJson(raw);
        const code = sanitizeCode(body.code);
        const err = new ApiError(410, message(body.detail, 410), code);
        if (
          (code === "account_deleted" || code === "gone") &&
          !sessionExpiredFired
        ) {
          sessionExpiredFired = true;
          sessionExpiredHandler?.(err, {
            userId: activeSession.userId,
            origin: activeSession.baseUrl,
            accountDeleted: true,
          });
        }
        throw err;
      }
      return response;
    } catch (err) {
      if (
        err instanceof ApiError &&
        err.status === 401 &&
        !sessionExpiredFired
      ) {
        // The one-shot expiry latch (same funnel as every gated request):
        // the app locks down instead of nursing a dead session.
        sessionExpiredFired = true;
        sessionExpiredHandler?.(err, {
          userId: activeSession.userId,
          origin: activeSession.baseUrl,
          accountDeleted: false,
        });
      }
      throw err;
    }
  },
  /** Mint a one-use, action-bound proof from a freshly derived verifier. */
  stepUp: (verifier: string, action: StepUpAction) =>
    request<{ proof: string; action: StepUpAction; expires_in: number }>(
      "POST",
      "/account/step-up",
      { verifier, action },
    ),
  /** Requires a fresh one-use account_delete proof. */
  deleteAccount: (stepUpProof: string) =>
    request<null>("DELETE", "/account", undefined, {
      "X-Step-Up-Proof": stepUpProof,
    }),
  getLlmConsent: () => request<LlmConsentState>("GET", "/account/llm-consent"),
  setLlmConsent: (enabled: boolean, stepUpProof: string) =>
    request<LlmConsentState>(
      "PUT",
      "/account/llm-consent",
      { enabled },
      { "X-Step-Up-Proof": stepUpProof },
    ),
  accessLogPage: async (
    cursor?: string,
  ): Promise<{
    rows: { at: string; action: string; actor: string }[];
    nextCursor: string | null;
  }> => {
    const response = await requestWithResponse<
      { at: string; action: string; actor: string }[]
    >(
      "GET",
      `/account/access-log${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""}`,
    );
    const rows = Array.isArray(response.data) ? response.data : [];
    const next = response.headers.get("X-Next-Cursor");
    return { rows, nextCursor: next && next.trim() ? next : null };
  },

  rekeyStoredData: (
    oldProcessingToken: string,
    newProcessingToken: string,
    verifierB64: string,
    credential: import("../localRotation").RotationCredential,
  ) =>
    request<{ credential_rotated: true; operation_id: string }>(
      "POST",
      "/processing/rekey",
      credential,
      {
        "X-Processing-Token": oldProcessingToken,
        "X-New-Processing-Token": newProcessingToken,
        "X-Account-Verifier": verifierB64,
      },
    ),
  rotateCredential: (
    oldVerifierB64: string,
    newSaltB64: string,
    newVerifierB64: string,
  ) =>
    request<null>("PUT", "/account/credential", {
      verifier: oldVerifierB64,
      new_salt: newSaltB64,
      new_verifier: newVerifierB64,
    }),

  /** The O(1) v2 password change (2026-09-26): swap salt + verifier + the
   *  re-wrapped data-key envelope in ONE server transaction. No rekey, no
   *  consent re-wrap — the data key itself never rotates. v2 accounts must
   *  use THIS route; the legacy PUT /account/credential answers them 409
   *  key_scheme_conflict (swapping the salt without re-wrapping the
   *  envelope would strand the random data key irrecoverably). Success
   *  bumps the token epoch — every session, this one included, dies with
   *  the 204; the caller locks down with honest copy.
   *  2026-09-28 audit M-1: the possession probe is required from EVERY
   *  caller — a processing session opened with the CURRENT data key rides
   *  as X-Processing-Token (the verifier proves the credential, not the
   *  key; only the probe authorizes replacing wrapped_data_key). */
  changePassword: (payload: {
    verifierB64: string;
    newSaltB64: string;
    newVerifierB64: string;
    wrappedDataKeyB64: string;
    newKdfParams?: Record<string, unknown>;
    processingToken: string;
  }) =>
    request<null>(
      "PUT",
      "/account/password",
      {
        verifier: payload.verifierB64,
        new_salt: payload.newSaltB64,
        new_verifier: payload.newVerifierB64,
        wrapped_data_key: payload.wrappedDataKeyB64,
        ...(payload.newKdfParams !== undefined
          ? { new_kdf_params: payload.newKdfParams }
          : {}),
      },
      { "X-Processing-Token": payload.processingToken },
    ),

  /** The v1→v2 self-upgrade (2026-09-26): after unlocking, wrap the
   *  account's CURRENT data key under the password-derived KEK and upload
   *  it. Two independent proofs ride the request: the account verifier
   *  (X-Account-Verifier — derived from the SAME password the KEK came
   *  from, so a mistyped password fails the verifier BEFORE any envelope
   *  is stored) and a live processing session opened with the current
   *  data key (X-Processing-Token — possession proof; 403
   *  envelope_key_mismatch means the session's key did not authenticate
   *  stored ciphertext). */
  upgradeKeyEnvelope: (
    wrappedDataKeyB64: string,
    kdfParams: Record<string, unknown>,
    processingToken: string,
    verifierB64: string,
  ) =>
    request<null>(
      "POST",
      "/account/key-envelope/upgrade",
      { kdf_params: kdfParams, wrapped_data_key: wrappedDataKeyB64 },
      {
        "X-Processing-Token": processingToken,
        "X-Account-Verifier": verifierB64,
      },
    ),

  pairingLookup: (code: string) =>
    request<PairingLookup>("POST", "/consents/pairing/lookup", { code }),
  grantConsent: (
    code: string,
    ephemeralPubB64: string,
    wrappedKeyB64: string,
    stepUpProof: string,
  ) =>
    request<ListedConsent>(
      "POST",
      "/consents",
      {
        code,
        ephemeral_pub: ephemeralPubB64,
        wrapped_key: wrappedKeyB64,
        disclosure: SHARING_DISCLOSURE_VERSION,
      },
      { "X-Step-Up-Proof": stepUpProof },
    ),
  listConsentsPage: async (
    params: { offset?: number; expectedRevision?: string } = {},
  ): Promise<ListedConsentsPage> => {
    const offset = params.offset ?? 0;
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > 1000) {
      throw new ApiError(0, "invalid consent page request");
    }
    if (
      params.expectedRevision !== undefined &&
      !isCanonicalRevision(params.expectedRevision)
    ) {
      throw new ApiError(0, "invalid consent page request");
    }
    const search = new URLSearchParams({
      limit: String(CONSENT_LIST_PAGE_SIZE),
      offset: String(offset),
    });
    if (params.expectedRevision !== undefined)
      search.set("expected_revision", params.expectedRevision);
    const response = await requestWithResponse<ListedConsent[]>(
      "GET",
      `/consents?${search.toString()}`,
    );
    if (
      !Array.isArray(response.data) ||
      response.data.length > CONSENT_LIST_PAGE_SIZE
    ) {
      throw new ApiError(0, "server returned an invalid consents page");
    }
    const revision = validatedRevision(
      response.headers.get("X-Consents-Revision"),
      undefined,
      "consents",
    );
    if (
      params.expectedRevision !== undefined &&
      revision !== params.expectedRevision
    ) {
      throw consentsRevisionConflict();
    }
    return {
      consents: response.data,
      nextOffset:
        response.headers.get("X-Next-Offset") === null
          ? revision === undefined &&
            response.data.length === CONSENT_LIST_PAGE_SIZE
            ? offset + response.data.length
            : null
          : validatedNextOffset(
              response.headers.get("X-Next-Offset"),
              offset,
              response.data.length,
              "consents",
            ),
      revision,
    };
  },
  listConsents: listConsentsWalk,
  rewrapConsent: (
    consentId: string,
    ephemeralPubB64: string,
    wrappedKeyB64: string,
    stepUpProof: string,
  ) => {
    if (!CONSENT_ID_PATTERN.test(consentId))
      throw new ApiError(0, "invalid consent id — refusing the request");
    return request<null>(
      "PUT",
      `/consents/${consentId}/rewrap`,
      { ephemeral_pub: ephemeralPubB64, wrapped_key: wrappedKeyB64 },
      { "X-Step-Up-Proof": stepUpProof },
    );
  },
  revokeConsent: (consentId: string, stepUpProof: string) => {
    if (!CONSENT_ID_PATTERN.test(consentId))
      throw new ApiError(0, "invalid consent id — refusing the request");
    return request<null>("DELETE", `/consents/${consentId}`, undefined, {
      "X-Step-Up-Proof": stepUpProof,
    });
  },
};

export type InsightsResponse = Awaited<ReturnType<typeof api.insights>>;

/** Fence every stream read, including callers consuming Response.body directly. */
function guardResponseStream(
  response: Response,
  controller: AbortController,
  cleanup: () => void,
  maxBytes: number,
): Response {
  if (!response.body) return response;
  const reader = response.body.getReader();
  let received = 0;
  let finished = false;
  const stream = new ReadableStream<Uint8Array>({
    start(target) {
      const abort = () => {
        if (!finished) {
          finished = true;
          target.error(new ApiError(0, "session ended or response timed out"));
          void reader.cancel().catch(() => undefined);
          cleanup();
        }
      };
      if (controller.signal.aborted) abort();
      else controller.signal.addEventListener("abort", abort, { once: true });
    },
    async pull(target) {
      if (finished) return;
      try {
        const row = await reader.read();
        if (finished || controller.signal.aborted) return;
        if (row.done) {
          finished = true;
          target.close();
          cleanup();
          return;
        }
        received += row.value.byteLength;
        if (received > maxBytes)
          throw new ApiError(
            0,
            "Server response exceeded this client's safe size limit.",
          );
        target.enqueue(row.value);
      } catch (err) {
        if (!finished) {
          finished = true;
          target.error(err);
          void reader.cancel().catch(() => undefined);
          cleanup();
        }
      }
    },
    cancel(reason) {
      finished = true;
      cleanup();
      return reader.cancel(reason);
    },
  });
  const guarded = new Response(stream, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
  Object.defineProperty(guarded, "url", { value: response.url });
  return guarded;
}
