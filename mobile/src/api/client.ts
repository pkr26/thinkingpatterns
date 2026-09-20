/**
 * Typed API client. The Authorization token never coexists with the password.
 *
 * Server URL policy: https is required for anything off-device. Plain http
 * is allowed only for the device-local loopback hosts used during development.
 * A bearer token, password verifier, or data key must never be sent over a
 * LAN/WAN cleartext connection, even after a modal "consent" click.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { secureStore } from "../secureStore";

/** Every endpoint is versioned under /api/v1. The server still mounts the
 *  legacy /api tree during the transition, but new clients speak v1 — the
 *  unified error envelope ({"detail", "code"}) is only guaranteed there. */
const API_PREFIX = "/api/v1";

const BASE_URL_KEY = "@mindpattern/base_url";
/** Legacy key retained only so an old cleartext-consent bit is actively
 * cleared on upgrade. It is never consulted to authorize a connection. */
const INSECURE_OK_KEY = "@mindpattern/insecure_http_ok";
const TOKEN_KEY = "@mindpattern/token";
const USER_ID_KEY = "@mindpattern/user_id";
const USERNAME_KEY = "@mindpattern/username";

/** Per-username KDF salt cache key. The salt itself is a PUBLIC value (the
 *  server hands it to anyone who asks) — but WHICH server it came from is
 *  not: a cached salt is stored origin-bound so one server's salt can never
 *  be replayed as another's (cross-origin KDF poisoning). */
const saltKey = (username: string): string => `@mindpattern/salt_${username}`;

export const DEFAULT_BASE_URL = "http://localhost:8000";

const REQUEST_TIMEOUT_MS = 15_000;
const MAX_ERROR_MESSAGE_CHARS = 200;
/** A server that always returns valid-looking continuations would loop
 * listEntries forever (memory exhaustion, battery drain). 100 pages is far
 * beyond any real journal; past that the server is hostile/broken. */
const MAX_LIST_PAGES = 100;
/** A changed snapshot is retryable, but never retry indefinitely under a
 * continuously-written journal. One clean restart obtains a fresh token; a
 * second conflict is surfaced to the caller honestly. */
const MAX_LIST_SNAPSHOT_RESTARTS = 1;
/** The backend's explicit byte-page ceiling for encrypted journal blobs.
 * Sending it on every modern list request opts into continuation headers,
 * rather than treating a byte-short response as end-of-history. */
export const ENTRY_PAGE_BYTES = 2 * 1024 * 1024;
/** Entry ids this client generates are [A-Za-z0-9_-]; anything else in this
 *  position is at-rest tampering and must never reach the URL path. The
 *  1-64 length band matches the backend exactly (backend/app/schemas.py
 *  CLIENT_ID_PATTERN) — a longer id would be built, queued and retried
 *  forever only to be 422'd at upload. */
const ENTRY_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

/** Consent ids are the server's 32-hex new_id(); the same URL-path hygiene
 *  as entry ids (backend/app/models.py new_id). */
const CONSENT_ID_PATTERN = /^[0-9a-f]{32}$/;

/** Which sharing-disclosure copy the grant flow showed; recorded on the
 *  consent row server-side (GDPR Art. 7 parity with the LLM consent).
 *  Keep in sync with backend/app/api/consents.py SHARING_DISCLOSURE_VERSION
 *  — bump BOTH when the disclosure copy changes.
 *  v2 (2026-09-20 audit H-14): the copy now names wellbeing measures
 *  (PHQ-9) and caseload summaries alongside entries and patterns — the
 *  Art. 7 record must state the real data scope. Legacy v1 consents stay
 *  active for entries/insights; the server gates measure reads on v2 and
 *  answers 409 disclosure_outdated, which the grant flow surfaces. */
export const SHARING_DISCLOSURE_VERSION = "v2";

/** A sharing consent as the patient's app renders it (backend ConsentOut).
 *  The server is untrusted; unknown fields pass through untouched. */
export interface ListedConsent {
  id: string;
  therapist_id: string;
  display_name: string;
  username: string;
  status: string;
  granted_at: string;
  revoked_at: string | null;
}

/** The pairing-lookup answer: who the code belongs to, before any data
 *  moves. The user sees exactly this before deciding to share. */
export interface PairingLookup {
  therapist_id: string;
  display_name: string;
  wrap_pub_key: string;
}

/** `URL#hostname` is canonicalized before it reaches this check. Keep the
 *  permitted development loopback set deliberately exact: a look-alike such
 *  as `localhost.` or `127.0.0.2` must still require TLS. */
function isExplicitLoopbackHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host === "::1";
}

/** Localhost, 127.0.0.1 and [::1] address the same device-local loopback
 *  interface — unify their spelling. Shared by the offline queue's storage
 *  scoping AND by request()'s origin pin (H-1): the queue canonicalizes the
 *  pin it passes, so the send-point comparison must canonicalize too, or a
 *  stored `localhost`/`[::1]` base URL makes every pinned upload throw
 *  OriginPinnedError BEFORE the network — under the shipped default server
 *  URL the queue could never flush at all. Canonicalizing only collapses
 *  loopback aliases; every real origin switch still trips the pin. */
export function canonicalOrigin(origin: string): string {
  try {
    const url = new URL(origin);
    // WHATWG serializes IPv6 hosts WITH brackets ("[::1]"); accept both
    // spellings so every loopback form maps to one canonical origin.
    const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
    if (host === "localhost" || host === "::1" || host === "127.0.0.1") {
      return `${url.protocol}//127.0.0.1${url.port ? `:${url.port}` : ""}`;
    }
    return origin;
  } catch {
    // Stryker disable next-line BlockStatement: unreachable for production inputs — canonicalOrigin only ever receives URL.origin output (always parseable); the guard exists for direct callers with arbitrary strings
    return origin;
  }
}

export function parseServerUrl(candidate: string): { url: string; insecure: boolean } | null {
  const trimmed = candidate.trim();
  // Keep the intentionally narrow product grammar (lowercase http(s), no
  // userinfo, query or fragment) while delegating authority/port/IPv6
  // validation to the platform URL parser. The old hand parser accepted an
  // invalid single-colon authority such as `https://api.example:abc` and
  // persisted it, leaving the next request to fail much later.
  if (!/^(https?):\/\/([^\s/?#@]+)(\/[^\s?#]*)?$/.test(trimmed)) return null;
  try {
    const parsed = new URL(trimmed);
    if (
      (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
      !parsed.hostname ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash
    ) {
      return null;
    }
    const path = parsed.pathname.replace(/\/+$/, "");
    return {
      url: `${parsed.origin}${path}`,
      insecure: parsed.protocol === "http:" && !isExplicitLoopbackHost(parsed.hostname),
    };
  } catch {
    return null;
  }
}

export async function getBaseUrl(): Promise<string> {
  return (await AsyncStorage.getItem(BASE_URL_KEY)) ?? DEFAULT_BASE_URL;
}

async function originOf(url: string): Promise<string> {
  return new URL(url).origin;
}

/** Return true only for the loopback development endpoints whose traffic
 * never leaves the device. `localhost.` and look-alike host names are not
 * loopback; keeping this deliberately exact avoids hostname-trick bypasses. */
function isLoopbackUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" && isExplicitLoopbackHost(parsed.hostname);
  } catch {
    return false;
  }
}

/**
 * A server-origin switch is a security boundary. The session provider
 * registers this synchronous hook to lock the in-memory vault and move the
 * navigator to logged-out before the new origin is persisted. Keeping the
 * hook here (instead of importing the store) avoids an api ↔ store cycle.
 */
let onOriginChange: (() => void | Promise<void>) | null = null;
export function setOriginChangeHandler(handler: (() => void | Promise<void>) | null): void {
  onOriginChange = handler;
}

/** Every per-account and per-origin local value: salts, unlock proofs,
 *  recompute stamps, mood logs, pending question feedback, queue
 *  quarantine. All of it belongs to the origin it was created against. */
function isOriginBoundKey(key: string): boolean {
  return (
    key.startsWith("@mindpattern/salt_") ||
    key.startsWith("@mindpattern/unlockproof_") ||
    key.startsWith("@mindpattern/last_recompute_") ||
    // Same prefix as questionFeedback.ts's key() — that module exports no
    // constant to import, so the literal is duplicated here on purpose.
    key.startsWith("@mindpattern/question_feedback.") ||
    key.startsWith("mindpattern.moodlog.") ||
    key.startsWith("@mindpattern/crisis_dialog_")
  );
}

export async function setBaseUrl(url: string, opts: { allowInsecure?: boolean } = {}): Promise<string | null> {
  void opts;
  const parsed = parseServerUrl(url);
  if (!parsed) return "Enter a full URL like https://your-server:8000 (no credentials in the URL).";
  // `allowInsecure` remains in the type for a source-compatible upgrade,
  // but cannot override the transport boundary. A user cannot meaningfully
  // consent away another app / Wi-Fi observer's ability to steal a bearer.
  if (parsed.insecure && !isLoopbackUrl(parsed.url)) {
    // Proactively retire an upgrade-era exception even though it is never
    // consulted. Leaving it around invites a later regression to revive it.
    await AsyncStorage.setItem(INSECURE_OK_KEY, "0");
    return "This server uses plain HTTP. Use HTTPS for any server other than localhost or 127.0.0.1.";
  }
  const previous = (await AsyncStorage.getItem(BASE_URL_KEY)) ?? DEFAULT_BASE_URL;
  let originChanged = false;
  try {
    originChanged = (await originOf(previous)) !== (await originOf(parsed.url));
  } catch {
    // An old/corrupt setting is never a reason to retain a live credential.
    originChanged = true;
  }
  if (originChanged) {
    // IMPORTANT ORDERING: erase the old credential BEFORE persisting the new
    // base URL. A request racing this function therefore either (a) reads the
    // old URL and can only send its token to its old origin, or (b) reads the
    // new URL after this wipe and has no token to attach. Persisting first was
    // a real bearer-token exfiltration window.
    await secureStore.removeItem(TOKEN_KEY);
    await secureStore.removeItem(USER_ID_KEY);
    await secureStore.removeItem(USERNAME_KEY);
    try {
      await onOriginChange?.();
    } catch {
      // Credential erasure is complete even if a UI subscriber has already
      // unmounted. Do not leave a half-switched origin because of that.
    }
    // KDF salts, unlock proofs, recompute stamps, mood logs and queue
    // quarantine data are equally origin-bound: one server's salt must
    // never be used to derive keys against another server's account.
    try {
      const keys = await AsyncStorage.getAllKeys();
      const stale = keys.filter(isOriginBoundKey);
      // Stryker disable next-line ConditionalExpression,EqualityOperator: stale is always an array (Array#filter), and multiRemove([]) is a documented no-op — an always-taken branch is unobservable
      if (stale.length > 0) await AsyncStorage.multiRemove(stale);
    } catch {
      // getAllKeys unavailable: the session wipe above is the critical part.
    }
  }
  await AsyncStorage.setItem(BASE_URL_KEY, parsed.url);
  // Remove a legacy consent value rather than carrying a cleartext exception
  // forward into a later client version.
  await AsyncStorage.setItem(INSECURE_OK_KEY, "0");
  return null; // null = saved
}

/** No-argument form: is ANY insecure consent currently stored (used for
 *  display). With a url: is THIS exact url the one consented to? */
export async function isInsecureHttpAllowed(url?: string): Promise<boolean> {
  void url;
  return false;
}

/** Retained as a source-compatible upgrade seam. No cleartext exception is
 * ever persisted or returned. */
export async function getInsecureConsentUrl(): Promise<string | null> {
  return null;
}

/**
 * Server-provided detail is attacker-controllable text (a hostile or
 * redirected server): cap length, strip URLs (ANY scheme — tel:,
 * custom-app schemes, not just http) and control characters so an error
 * dialog cannot be turned into a phishing surface.
 */
function sanitizeDetail(text: string): string {
  const stripped = text
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    // Bidi overrides / isolates and zero-width characters: invisible
    // homoglyph tricks that can flip or disguise error-dialog text.
    // U+2060-U+206F (word joiner, invisible math/operators) and U+FEFF
    // joined the strip set on 2026-09-19: the audit smuggled a word joiner
    // INSIDE a domain ("bit\u2060.ly") so the domain rules below never
    // matched it. Invisibles go FIRST so the domain regexes see the
    // cleaned text.
    .replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g, "")
    .replace(/https?:\/\/\S+/gi, "")
    // Any other scheme://… (evilapp://pay, ftp://…) — same phishing class;
    // the scheme AND its payload go, like the http case above.
    .replace(/[a-z][a-z0-9+.-]*:\/\/\S+/gi, "")
    // Scheme-less domains ("go to evil.com/support") — the 2026-09-16
    // red-team corpus showed the scheme regexes alone leave these intact.
    // ANY alpha TLD of 2-24 chars, never an allowlist: the 2026-09-19
    // audit walked bit.ly / mindpattern-support.de / discord.gg straight
    // through the old com|net|org|… list. Over-stripping ("node.js" in a
    // stack trace) is the safe direction for attacker-controlled text.
    .replace(/\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b(?::\d+)?(?:\/\S*)?/gi, "")
    // Phone-like digit runs ("call 555-0134") — separators included.
    .replace(/\d[\d\s().-]{2,}\d/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return stripped.length > MAX_ERROR_MESSAGE_CHARS
    ? `${stripped.slice(0, MAX_ERROR_MESSAGE_CHARS)}…`
    : stripped;
}

/** FastAPI validation errors put a list of message objects in `detail`.
 *  Exported for tests: the sanitization is a security property. */
export function detailToMessage(detail: unknown, status: number): string {
  if (typeof detail === "string") return sanitizeDetail(detail) || `request failed (${status})`;
  if (Array.isArray(detail)) {
    const parts = detail.map((d) =>
      typeof d === "object" && d !== null && "msg" in d && typeof (d as { msg: unknown }).msg === "string"
        ? (d as { msg: string }).msg
        : "invalid field",
    );
    // Stryker disable next-line ConditionalExpression,EqualityOperator: parts mirrors detail's length, so the only reachable false case is detail === []; [].join("; ") sanitizes to "" which falls to the identical `request failed (${status})` fallback
    if (parts.length > 0) return sanitizeDetail(parts.join("; ")) || `request failed (${status})`;
  }
  return `request failed (${status})`;
}

/** The server's unified error codes (v1 contract). Consumers branch on the
 *  machine-readable code first and fall back to status/detail for legacy
 *  servers that predate the envelope. */
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
  "entry_blob_invalid",
  "entry_payload_malformed",
  "feedback_blob_invalid",
  // 2026-09-20 audit H-14: the server returns this 409 when a legacy v1
  // sharing consent cannot cover a measures read; TherapistShareScreen
  // branches on it to show the calm "sharing terms updated" state.
  "disclosure_outdated",
] as const;
export type ApiErrorCode = (typeof API_ERROR_CODES)[number];

/** A code is attacker-controllable text like `detail`, but it feeds BRANCH
 *  logic, not dialogs: accept only the known slugs (anything else degrades
 *  to undefined, and the caller falls back to status/detail matching). */
function sanitizeCode(code: unknown): ApiErrorCode | undefined {
  // Stryker disable next-line ConditionalExpression: Array#includes uses SameValueZero, so any non-string code is never equal to a string slug — the typeof arm is fully subsumed by the includes check
  return typeof code === "string" && (API_ERROR_CODES as readonly string[]).includes(code)
    ? (code as ApiErrorCode)
    : undefined;
}

/** Retry-After on a 429 (or a 503 — the backend emits it there too) is
 *  seconds (or an HTTP-date); it is untrusted input — clamp to a sane
 *  ceiling so a hostile server cannot park the queue for days. Returns
 *  undefined when absent or unparseable. */
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

/** Session-death hook: invoked on ANY authenticated 401 BEFORE the
 *  ApiError is thrown, so every call site (entry save, insights fetch,
 *  question fetch, queue flush) reacts identically instead of each
 *  growing its own handler. Set once by the session store, where the
 *  vault lives; a failed login/register 401 carries no token and does
 *  NOT trip it (that 401 means "bad credentials", not "session died"). */
let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(handler: (() => void) | null): void {
  onUnauthorized = handler;
}

interface RequestOptions {
  /** The request ships a credential that must never survive a redirect
   *  (verifier, data key). For these, an unverifiable final URL — some
   *  network stacks leave response.url empty — is treated as a redirect
   *  failure, not silently accepted. */
  sensitive?: boolean;
  /** A small number of endpoints need response metadata in addition to the
   * JSON body (currently the byte-paginated entries continuation).  Keep the
   * common request path and all of its redirect/auth/error hardening rather
   * than reimplementing fetch for a single header. */
  includeResponse?: boolean;
  /** Pin this request to one API origin. The offline queue sets it so a
   *  server switch (and re-login) between two queue uploads can never send
   *  the old origin's ciphertext — under the new account's bearer — to the
   *  newly selected server. Checked after the current base URL is resolved
   *  and BEFORE a token is read or attached. */
  expectedOrigin?: string;
  /** This request authenticates by verifier (auth/login), not by bearer:
   *  send no Authorization header, and never treat its 401 as a dead
   *  session. A wrong password during a biometric session's online
   *  re-verification (reauth) would otherwise fire the vault-lock hook
   *  under the "wrong password" alert — fail-closed but disorienting
   *  (H-2 verification note, 2026-09-20). */
  noBearer?: boolean;
}

/** Raised locally (no request is sent) when an origin-pinned request finds
 *  the persisted server selection has moved. Not an ApiError: nothing
 *  reached the network, so callers must not classify it as a server
 *  response. */
export class OriginPinnedError extends Error {
  constructor(expected: string, actual: string) {
    super(`refusing to send data pinned to ${expected} while ${actual} is selected`);
    this.name = "OriginPinnedError";
  }
}

async function request(
  method: string,
  path: string,
  body?: unknown,
  extraHeaders: Record<string, string> = {},
  opts: RequestOptions = {},
): Promise<any> {
  const base = await getBaseUrl();
  const actualOrigin = new URL(base).origin;
  // H-1: the offline queue pins uploads to the CANONICAL loopback spelling
  // of its scope; a stored base URL may spell the same device-local server
  // as `localhost`, `127.0.0.1` or `[::1]`. Canonicalize BOTH sides of the
  // comparison (idempotent) so alias spellings of one loopback interface
  // pass while every genuinely different origin still refuses.
  if (
    opts.expectedOrigin !== undefined &&
    canonicalOrigin(actualOrigin) !== canonicalOrigin(opts.expectedOrigin)
  ) {
    throw new OriginPinnedError(opts.expectedOrigin, actualOrigin);
  }
  // Settings validates before persisting, but AsyncStorage can be restored
  // from an older backup or tampered with. Enforce the transport boundary at
  // the send point too, before reading/attaching a bearer credential.
  const configured = parseServerUrl(base);
  if (!configured || (configured.insecure && !isLoopbackUrl(configured.url))) {
    throw new ApiError(0, "refusing to send data to an invalid or cleartext remote server URL");
  }
  const token = opts.noBearer ? null : await secureStore.getItem(TOKEN_KEY);
  const headers: Record<string, string> = { "Content-Type": "application/json", ...extraHeaders };
  if (token) headers.Authorization = `Bearer ${token}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetch(`${base}${path}`, {
      method,
      headers,
      // JSON.stringify(undefined) is undefined: GETs send no body.
      body: JSON.stringify(body),
      signal: controller.signal,
      // Fetch implementations that honor this option must fail before
      // reissuing Authorization at a redirect target. The final-url check
      // below remains a defense for React Native stacks that ignore it.
      redirect: "error",
    });
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") {
      throw new ApiError(0, `request timed out after ${REQUEST_TIMEOUT_MS / 1000}s`);
    }
    throw new ApiError(0, "server unreachable — check the server URL or your connection");
    // A timer firing after the request settled only aborts an already-finished
    // signal — unobservable; skipping clearTimeout merely leaks one timer.
  } finally {
    clearTimeout(timer);
  }
  // RN's fetch follows redirects transparently and re-sends the headers: a
  // hostile server can bounce a request to another origin. The leak happens
  // on the first hop and cannot be undone — but refusing the response
  // bounds it to that single hop, and for sensitive requests (verifier /
  // data key) an UNVERIFIABLE final URL is refused outright rather than
  // silently trusted.
  const finalUrl = typeof response.url === "string" ? response.url : "";
  if (finalUrl === "" && opts.sensitive) {
    throw new ApiError(0, "could not verify this request was not redirected — check your server URL");
  }
  if (finalUrl !== "") {
    try {
      if (new URL(finalUrl).origin !== (await originOf(base))) {
        throw new ApiError(0, "server redirected the request off the configured origin — check your server URL");
      }
    } catch (err) {
      // Stryker disable next-line ConditionalExpression: both arms throw an ApiError with status 0 and the identical redirected-origin message — rethrow vs re-wrap is indistinguishable
      if (err instanceof ApiError) throw err;
      // An unparseable final URL degrades to the same refusal.
      throw new ApiError(0, "server redirected the request off the configured origin — check your server URL");
    }
  }
  if (response.status === 204) return opts.includeResponse ? { data: null, response } : null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && token !== null) {
      // The bearer token we sent was rejected: the session is dead. Lock
      // the vault app-wide BEFORE the caller sees the error — a hook
      // failure must never mask the 401 itself.
      try {
        // Stryker disable next-line OptionalChaining: the call is wrapped in a catch that swallows everything, so onUnauthorized() on a null handler throws the same-swallowed TypeError
        onUnauthorized?.();
      } catch {
        // a hook must never mask the ApiError below
      }
    }
    // Some network stacks / mocked responses carry no headers object at
    // all — treat Retry-After as absent rather than crashing the path.
    // L-54: the backend attaches Retry-After to 503 maintenance responses
    // as well as 429s; parsing only 429 made the offline queue fall back to
    // its 30 s+ exponential backoff on an explicit server advisory.
    const retryAfter =
      (response.status === 429 || response.status === 503) && typeof response.headers?.get === "function"
        ? parseRetryAfter(response.headers.get("retry-after"))
        : undefined;
    throw new ApiError(
      response.status,
      detailToMessage((data as { detail?: unknown }).detail, response.status),
      sanitizeCode((data as { code?: unknown }).code),
      retryAfter,
    );
  }
  return opts.includeResponse ? { data, response } : data;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    /** Machine-readable v1 error code; undefined on legacy servers. */
    public code?: ApiErrorCode,
    /** Server-advised retry delay (429/503 Retry-After), clamped; else absent. */
    public retryAfterMs?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** The owner-entry paging contract uses 409 for a stale snapshot token. It
 * is safe to retry from page zero, unlike an arbitrary mutation conflict. */
function entriesRevisionConflict(): ApiError {
  return new ApiError(409, "entries changed while paging; retry the request", "collection_changed");
}

/** One entry row as the backend serializes it (EntryOut). The server is
 *  untrusted — this types the shape for callers, it is not a guarantee, and
 *  unknown extra fields (e.g. a future "sensitive" flag) pass through
 *  untouched: nothing here strips or rejects them. */
export interface ListedEntry {
  id: string;
  client_entry_id: string;
  blob: string;
  entry_date: string;
  received_at: string;
}

/** Strict wire representation for an owner-journal snapshot revision. Keep
 * this as a string: the backend permits the full signed-64-bit range, which
 * JavaScript Numbers cannot represent exactly. */
export type EntriesRevision = string;

/** A byte-bounded entry response. `nextOffset` is present only when the
 * server has more rows, and is validated before callers can act on it.
 * `revision` is null for a legacy server that does not support stable
 * snapshots. */
export interface ListedEntriesPage {
  entries: ListedEntry[];
  nextOffset: number | null;
  revision: EntriesRevision | null;
}

export interface ListEntriesPageOptions {
  since?: string;
  limit?: number;
  offset?: number;
  pageBytes?: number;
  /** A revision returned by a preceding page. The wire name is
   * `expected_revision`; supplying it makes a changed collection return 409
   * instead of silently mixing two snapshots. */
  expectedRevision?: EntriesRevision;
}

function invalidEntryPageResponse(): never {
  throw new ApiError(0, "invalid entry page response — refusing the response");
}

/** Parse the paging signal as a strict, non-ambiguous integer. The modern
 * server promises offset + returned-row-count, so accepting a guessed or
 * malformed offset could skip history or create an unbounded sync loop. An
 * older server ignores `page_bytes` and has no header; its only safe fallback
 * is the legacy rule that an exactly-full requested page has another page. */
function entryNextOffset(header: string | null, offset: number, entries: ListedEntry[], limit: number): number | null {
  if (entries.length > limit) invalidEntryPageResponse();
  const expected = offset + entries.length;
  if (!Number.isSafeInteger(expected)) invalidEntryPageResponse();
  if (header === null) return entries.length === limit ? expected : null;
  if (!/^(?:0|[1-9][0-9]*)$/.test(header)) invalidEntryPageResponse();
  const nextOffset = Number(header);
  if (
    !Number.isSafeInteger(nextOffset) ||
    entries.length === 0 ||
    nextOffset !== expected
  ) {
    invalidEntryPageResponse();
  }
  return nextOffset;
}

/** The backend's canonical nonnegative signed-64-bit decimal grammar. Do
 * not use Number() here: revisions above Number.MAX_SAFE_INTEGER would be
 * rounded and could turn a valid snapshot token into a different request. */
const ENTRY_REVISION_PATTERN = /^(?:0|[1-9][0-9]{0,18})$/;
const MAX_ENTRY_REVISION = "9223372036854775807";

function isEntriesRevision(value: unknown): value is EntriesRevision {
  return (
    typeof value === "string" &&
    ENTRY_REVISION_PATTERN.test(value) &&
    (value.length < MAX_ENTRY_REVISION.length || value <= MAX_ENTRY_REVISION)
  );
}

function entryRevision(header: string | null): EntriesRevision | null {
  if (header === null) return null; // headerless servers retain legacy paging
  if (!isEntriesRevision(header)) invalidEntryPageResponse();
  return header;
}

export const api = {
  setSession: async (token: string, userId: string, username?: string) => {
    // All three values are session material and live encrypted at rest
    // (see secureStore): a device backup must not contain a usable token.
    await secureStore.setItem(TOKEN_KEY, token);
    await secureStore.setItem(USER_ID_KEY, userId);
    if (username !== undefined) await secureStore.setItem(USERNAME_KEY, username);
  },
  getUserId: async () => secureStore.getItem(USER_ID_KEY),
  getUsername: async () => secureStore.getItem(USERNAME_KEY),
  clearSession: async () => {
    await secureStore.removeItem(TOKEN_KEY);
    await secureStore.removeItem(USER_ID_KEY);
    await secureStore.removeItem(USERNAME_KEY);
  },
  isLoggedIn: async () => (await secureStore.getItem(TOKEN_KEY)) !== null,

  meta: () => request("GET", `${API_PREFIX}/meta`),

  register: (username: string, saltB64: string, authKeyB64: string) =>
    request("POST", `${API_PREFIX}/auth/register`, { username, salt: saltB64, verifier: authKeyB64 }, {}, { sensitive: true }),
  // POST body, never a URL path: usernames must not land in proxy access logs.
  saltFor: (username: string) => request("POST", `${API_PREFIX}/auth/salt`, { username }),
  cacheSalt: async (username: string, saltB64: string) => {
    // Bind the salt to the origin it was served from: an offline unlock
    // under server B must never derive keys with server A's salt.
    // v1 envelope: pre-v1 records were a bare { o, s } — see getCachedSalt.
    const record = JSON.stringify({ v: 1, o: await getBaseUrl(), s: saltB64 });
    await AsyncStorage.setItem(saltKey(username), record);
  },
  /** The last server-known salt for this username FROM THE CURRENT SERVER,
   *  or null. Enables offline vault unlock without cross-origin replay. */
  getCachedSalt: async (username: string) => {
    const raw = await AsyncStorage.getItem(saltKey(username));
    // Stryker disable next-line ConditionalExpression: with the guard skipped, JSON.parse of a falsy raw ("" / null) throws or yields null inside the try below, and the catch returns the same null
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw) as { v?: unknown; o?: unknown; s?: unknown };
      // v1 envelope, or the legacy bare { o, s } shape (no v field) — both
      // carry the same two strings; anything else refuses rather than guesses.
      const legacy = parsed.v === undefined;
      if (!(legacy || parsed.v === 1)) return null;
      if (typeof parsed.o !== "string" || typeof parsed.s !== "string") return null;
      if (parsed.o !== (await getBaseUrl())) return null;
      // Stryker disable next-line ConditionalExpression: the read-through rewrite stores {v:1,o,s} — for already-v1 records that is a byte-identical (or normalizing) no-op write, and the returned salt never changes
      if (legacy) {
        // Read-through migration (same idiom as the mood log): refresh the
        // record to the v1 envelope so the legacy window stays bounded. A
        // failed rewrite never fails the read.
        await AsyncStorage.setItem(saltKey(username), JSON.stringify({ v: 1, o: parsed.o, s: parsed.s })).catch(
          () => {},
        );
      }
      return parsed.s;
    } catch {
      return null; // legacy/corrupt record: refuse rather than guess
    }
  },
  clearCachedSalt: async (username: string) => {
    await AsyncStorage.removeItem(saltKey(username));
  },
  login: (username: string, authKeyB64: string) =>
    // noBearer: a login 401 means the VERIFIER was wrong (wrong password),
    // never that the stored bearer died — so the vault-lock hook must not
    // fire on it (biometric sessions use this endpoint for the online
    // re-auth check; see reauth.ts).
    request("POST", `${API_PREFIX}/auth/login`, { username, verifier: authKeyB64 }, {}, { sensitive: true, noBearer: true }),
  /** Server-side kill switch: invalidates every bearer token for the account. */
  logout: () => request("POST", `${API_PREFIX}/auth/logout`),

  createEntry: (clientEntryId: string, blobB64: string, entryDate: string) =>
    request("POST", `${API_PREFIX}/entries`, { client_entry_id: clientEntryId, blob: blobB64, entry_date: entryDate }),
  /** MBC measures (2026-09-19): opaque encrypted questionnaire records. */
  createMeasure: (clientMeasureId: string, blobB64: string, measureDate: string) =>
    request(
      "POST",
      `${API_PREFIX}/measures`,
      { client_measure_id: clientMeasureId, blob: blobB64, measure_date: measureDate },
    ),
  /** One offset page of the patient's own measures, newest first (the
   *  server orders by (measure_date, received_at, id) DESC — a
   *  deterministic total order, so offset pages tile cleanly). */
  listMeasuresPage: (limit: number, offset: number) => {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    return request("GET", `${API_PREFIX}/measures?${params.toString()}`);
  },
  /** All stored measures, newest first. M-4/L-55 (2026-09-20): the write
   *  quota is 2000 but a single unpaged GET returned only the server's
   *  default page of 100 — everything older was stored and quota-charged
   *  yet invisible to the patient. Walk offset pages of the server cap
   *  (500) until a short page, dedup by id (a concurrent insert shifts
   *  offset windows by one), and stop at the quota bound so a lying
   *  server cannot keep the app paging forever. */
  listMeasures: async (): Promise<any[]> => {
    const PAGE_SIZE = 500;
    const MAX_MEASURES = 2000; // mirrors the server's per-user quota
    const rows: any[] = [];
    const seen = new Set<string>();
    for (let offset = 0; offset < MAX_MEASURES; offset += PAGE_SIZE) {
      const page = (await request("GET", `${API_PREFIX}/measures?limit=${PAGE_SIZE}&offset=${offset}`)) as any[];
      if (!Array.isArray(page)) return rows;
      for (const row of page) {
        if (row && typeof row.id === "string") {
          if (seen.has(row.id)) continue;
          seen.add(row.id);
        }
        rows.push(row);
      }
      if (page.length < PAGE_SIZE) break;
    }
    return rows;
  },
  /** Offline-queue upload. Identical to createEntry but pinned to the origin
   *  the queue is scoped to: the request refuses to ship (OriginPinnedError,
   *  nothing sent) if the selected server moved, so queued ciphertext can
   *  never ride a different origin's credentials. */
  createQueuedEntry: (clientEntryId: string, blobB64: string, entryDate: string, expectedOrigin: string) =>
    request(
      "POST",
      `${API_PREFIX}/entries`,
      { client_entry_id: clientEntryId, blob: blobB64, entry_date: entryDate },
      {},
      { expectedOrigin },
    ),
  /** Atomically replace an existing encrypted entry. The client id stays
   * stable, so the encrypted blob remains AAD-bound to the same account and
   * record. This deliberately avoids delete-then-create data loss. */
  updateEntry: async (clientEntryId: string, blobB64: string, entryDate: string) => {
    if (!ENTRY_ID_PATTERN.test(clientEntryId)) {
      throw new ApiError(0, "invalid entry id — refusing the request");
    }
    return request(
      "PUT",
      `${API_PREFIX}/entries/${encodeURIComponent(clientEntryId)}`,
      { blob: blobB64, entry_date: entryDate },
    );
  },
  /** One bounded ciphertext page. Screens use this rather than materializing
   * an entire multi-year journal in JS memory. */
  listEntriesPage: async (options: ListEntriesPageOptions = {}): Promise<ListedEntriesPage> => {
    const limit = options.limit ?? 100;
    const offset = options.offset ?? 0;
    const pageBytes = options.pageBytes ?? ENTRY_PAGE_BYTES;
    if (
      !Number.isInteger(limit) ||
      limit < 1 ||
      limit > 500 ||
      !Number.isSafeInteger(offset) ||
      offset < 0 ||
      !Number.isInteger(pageBytes) ||
      pageBytes < 1 ||
      pageBytes > ENTRY_PAGE_BYTES ||
      (options.expectedRevision !== undefined && !isEntriesRevision(options.expectedRevision))
    ) {
      throw new ApiError(0, "invalid entry page request — refusing the request");
    }
    const params = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
      page_bytes: String(pageBytes),
    });
    if (options.since) params.set("since", options.since);
    if (options.expectedRevision !== undefined) params.set("expected_revision", options.expectedRevision);
    const result = (await request(
      "GET",
      `${API_PREFIX}/entries?${params.toString()}`,
      undefined,
      {},
      { includeResponse: true },
    )) as { data: unknown; response: Response };
    if (!Array.isArray(result.data)) invalidEntryPageResponse();
    const entries = result.data as ListedEntry[];
    const nextOffsetHeader =
      typeof result.response.headers?.get === "function" ? result.response.headers.get("X-Next-Offset") : null;
    const revisionHeader =
      typeof result.response.headers?.get === "function" ? result.response.headers.get("X-Entries-Revision") : null;
    const revision = entryRevision(revisionHeader);
    // A modern server must echo the exact snapshot on every successful page.
    // Treat a missing/different header as a retryable conflict rather than
    // allowing a mixed history to reach the decrypting UI. Headerless legacy
    // servers never receive expected_revision in the first place.
    if (options.expectedRevision !== undefined && revision !== options.expectedRevision) {
      throw entriesRevisionConflict();
    }
    return { entries, nextOffset: entryNextOffset(nextOffsetHeader, offset, entries, limit), revision };
  },
  /** Paginates through every byte-bounded page (server caps each request at
   * 500 entries and 2 MiB of encrypted blobs). Modern servers issue a
   * snapshot revision on page one; every continuation sends it back so a
   * concurrent write returns retryable 409 rather than causing offset drift.
   * Headerless servers retain the established dedupe-only fallback. */
  listEntries: async (since?: string): Promise<ListedEntry[]> => {
    for (let attempt = 0; attempt <= MAX_LIST_SNAPSHOT_RESTARTS; attempt += 1) {
      try {
        const all: ListedEntry[] = [];
        const seen = new Set<string>();
        const pageSize = 500;
        let offset = 0;
        let revision: EntriesRevision | null = null;
        let revisionMode: "unknown" | "snapshot" | "legacy" = "unknown";
        const getPage = async (pageOffset: number): Promise<ListedEntriesPage> => {
          const result = await api.listEntriesPage({
            since,
            limit: pageSize,
            offset: pageOffset,
            pageBytes: ENTRY_PAGE_BYTES,
            ...(revisionMode === "snapshot" && revision !== null ? { expectedRevision: revision } : {}),
          });
          // `revision` is always null|string from the real client. The nullish
          // fallback also keeps older test doubles and external callers on the
          // documented headerless path rather than accidentally sending
          // `expected_revision=undefined`.
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
            throw entriesRevisionConflict();
          }
          return result;
        };
        for (let page = 0; page < MAX_LIST_PAGES; page++) {
          const result = await getPage(offset);
          for (const entry of result.entries) {
            if (seen.has(entry.client_entry_id)) continue; // legacy page-boundary drift
            seen.add(entry.client_entry_id);
            all.push(entry);
          }
          if (result.nextOffset === null) return all;
          offset = result.nextOffset;
        }
        // A header-less legacy server cannot distinguish exactly MAX_LIST_PAGES
        // full pages from one more page. Permit one *empty* terminal probe so a
        // 50k-row journal does not falsely fail at the boundary; never retain a
        // nonempty overflow response, which preserves the aggregate cap.
        const probe = await getPage(offset);
        if (probe.entries.length === 0 && probe.nextOffset === null) return all;
        // A hostile or broken server has more entries than the bounded sync may
        // retain. The probe is deliberately inspected before its rows reach
        // `all`, so the cap is real rather than merely a loop-count guard.
        throw new ApiError(0, "server keeps returning entry continuations — aborting sync, contact support or check the server");
      } catch (err) {
        if (err instanceof ApiError && err.status === 409 && attempt < MAX_LIST_SNAPSHOT_RESTARTS) continue;
        throw err;
      }
    }
    throw new ApiError(0, "could not obtain a stable journal history snapshot");
  },
  deleteEntry: async (clientEntryId: string) => {
    // The id lands in the URL path: validate the exact shape this client
    // generates so at-rest tampering cannot steer the authenticated DELETE
    // at an arbitrary endpoint.
    if (!ENTRY_ID_PATTERN.test(clientEntryId)) {
      throw new ApiError(0, "invalid entry id — refusing the request");
    }
    return request("DELETE", `${API_PREFIX}/entries/${encodeURIComponent(clientEntryId)}`);
  },

  /** The data key is the whole journal. The app transport policy already
   * refuses every remote plain-HTTP server; retain this local check as a
   * defence-in-depth guard for a corrupted persisted base URL. */
  openProcessingSession: async (dataKeyB64: string) => {
    const parsed = parseServerUrl(await getBaseUrl());
    if (parsed && parsed.insecure) {
      throw new ApiError(
        0,
        "the encryption key can only be sent over HTTPS (or localhost) — update the server URL",
      );
    }
    return request("POST", `${API_PREFIX}/processing/sessions`, { data_key: dataKeyB64 }, {}, { sensitive: true });
  },
  recompute: (processingToken: string, feedbackBlob?: string) =>
    request(
      "POST",
      `${API_PREFIX}/insights/recompute`,
      feedbackBlob ? ({ feedback_blob: feedbackBlob } as Record<string, unknown>) : undefined,
      { "X-Processing-Token": processingToken },
    ),
  insights: () => request("GET", `${API_PREFIX}/insights`),
  questionToday: () => request("GET", `${API_PREFIX}/questions/today`),

  exportAccount: () => request("GET", `${API_PREFIX}/account/export`),
  /** Requires the password-derived verifier: a stolen token cannot erase
   *  data. The verifier travels in the X-Account-Verifier header (the v1
   *  preference), never the URL; the server still accepts the legacy body
   *  field during the transition. */
  deleteAccount: (verifierB64: string) =>
    request("DELETE", `${API_PREFIX}/account`, undefined, { "X-Account-Verifier": verifierB64 }, { sensitive: true }),
  /** Explicit, re-authenticated opt-in for third-party LLM analysis. */
  getLlmConsent: () => request("GET", `${API_PREFIX}/account/llm-consent`),
  setLlmConsent: (enabled: boolean, verifierB64: string) =>
    request("PUT", `${API_PREFIX}/account/llm-consent`, { enabled, verifier: verifierB64 }, {}, { sensitive: true }),

  // --- therapist sharing (2026-09-16) ---------------------------------------
  /** Resolve a pairing code to WHO it belongs to. No data moves yet — the
   *  user must see the therapist's name before confirming anything. */
  pairingLookup: (code: string): Promise<PairingLookup> =>
    request("POST", `${API_PREFIX}/consents/pairing/lookup`, { code }),
  /** Grant sharing: the wrapped data key ships once, verifier-gated (the
   *  verifier header carries the password proof; sensitive = redirect-refused). */
  grantConsent: (
    code: string,
    ephemeralPubB64: string,
    wrappedKeyB64: string,
    verifierB64: string,
  ): Promise<ListedConsent> =>
    request(
      "POST",
      `${API_PREFIX}/consents`,
      { code, ephemeral_pub: ephemeralPubB64, wrapped_key: wrappedKeyB64, disclosure: SHARING_DISCLOSURE_VERSION },
      { "X-Account-Verifier": verifierB64 },
      { sensitive: true },
    ),
  listConsents: (): Promise<ListedConsent[]> => request("GET", `${API_PREFIX}/consents`),
  /** Revoke: verifier-gated like every disclosure-widening/narrowing action. */
  revokeConsent: async (consentId: string, verifierB64: string) => {
    if (!CONSENT_ID_PATTERN.test(consentId)) {
      throw new ApiError(0, "invalid consent id — refusing the request");
    }
    return request(
      "DELETE",
      `${API_PREFIX}/consents/${consentId}`,
      undefined,
      { "X-Account-Verifier": verifierB64 },
      { sensitive: true },
    );
  },
};
