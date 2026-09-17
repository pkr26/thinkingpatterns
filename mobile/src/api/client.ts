/**
 * Typed API client. The Authorization token never coexists with the password.
 *
 * Server URL policy: https is required for anything off-device. Plain http
 * is allowed ONLY for localhost/loopback development servers, or for the
 * exact insecure URL the user explicitly consented to (per-URL consent —
 * allowing http://nas.lan never blesses any other host).
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { secureStore } from "../secureStore";

/** Every endpoint is versioned under /api/v1. The server still mounts the
 *  legacy /api tree during the transition, but new clients speak v1 — the
 *  unified error envelope ({"detail", "code"}) is only guaranteed there. */
const API_PREFIX = "/api/v1";

const BASE_URL_KEY = "@mindpattern/base_url";
/** Stores the exact URL the user consented to for plain HTTP (not a
 *  sticky global flag: consenting to one host must not silently bless
 *  every other cleartext server). Empty/"0" = no consent. */
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
/** A server that always returns a full page would loop listEntries
 *  forever (memory exhaustion, battery drain). 100 pages = 50k entries —
 *  far beyond any real journal; past that the server is hostile/broken. */
const MAX_LIST_PAGES = 100;
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
 *  — bump BOTH when the disclosure copy changes. */
export const SHARING_DISCLOSURE_VERSION = "v1";

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

export function parseServerUrl(candidate: string): { url: string; insecure: boolean } | null {
  const trimmed = candidate.trim();
  const match = /^(https?):\/\/([^\s/?#@]+)(\/[^\s?#]*)?$/.exec(trimmed);
  if (!match) return null;
  // The regex guarantees non-empty scheme and host; the assertions only
  // satisfy noUncheckedIndexedAccess.
  const scheme = match[1]!;
  const host = match[2]!;
  const path = match[3] ?? "";
  if (/:.*:/.test(host) && !host.startsWith("[")) return null; // mangled IPv6
  const url = `${scheme}://${host}${path.replace(/\/+$/, "")}`;
  const isLoopback = /^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(host);
  const insecure = scheme === "http" && !isLoopback;
  return { url, insecure };
}

export async function getBaseUrl(): Promise<string> {
  return (await AsyncStorage.getItem(BASE_URL_KEY)) ?? DEFAULT_BASE_URL;
}

async function originOf(url: string): Promise<string> {
  return new URL(url).origin;
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
    key === "@mindpattern/queue_quarantine" ||
    key === "@mindpattern/queue_rejected"
  );
}

export async function setBaseUrl(url: string, opts: { allowInsecure?: boolean } = {}): Promise<string | null> {
  const parsed = parseServerUrl(url);
  if (!parsed) return "Enter a full URL like https://your-server:8000 (no credentials in the URL).";
  if (parsed.insecure && !opts.allowInsecure) {
    return "This server uses plain HTTP. To accept the risk, use 'Allow insecure HTTP' first.";
  }
  const previous = await AsyncStorage.getItem(BASE_URL_KEY);
  await AsyncStorage.setItem(BASE_URL_KEY, parsed.url);
  const originChanged = previous !== null && previous !== parsed.url;
  if (originChanged) {
    // Origin change: the stored session (token, user id, username) belongs to
    // the OLD origin — leaving it in place would send live credentials to the
    // new server on the very next request. The user re-authenticates against
    // the new origin instead.
    await secureStore.removeItem(TOKEN_KEY);
    await secureStore.removeItem(USER_ID_KEY);
    await secureStore.removeItem(USERNAME_KEY);
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
  // Consent is recorded for THIS url only; saving any other URL (secure or
  // otherwise) clears it, so consent can never outlive its server.
  await AsyncStorage.setItem(
    INSECURE_OK_KEY,
    parsed.insecure && opts.allowInsecure ? parsed.url : "0",
  );
  return null; // null = saved
}

/** No-argument form: is ANY insecure consent currently stored (used for
 *  display). With a url: is THIS exact url the one consented to? */
export async function isInsecureHttpAllowed(url?: string): Promise<boolean> {
  const stored = await getInsecureConsentUrl();
  if (stored === null) return false;
  return url === undefined ? true : stored === url;
}

/** The exact URL the user consented to for plain HTTP (or null). UI keeps
 *  this in state so a save never blocks on (or skips past) the check. */
export async function getInsecureConsentUrl(): Promise<string | null> {
  const stored = await AsyncStorage.getItem(INSECURE_OK_KEY);
  return stored && stored !== "0" ? stored : null;
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
    .replace(/[\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, "")
    .replace(/https?:\/\/\S+/gi, "")
    // Any other scheme://… (evilapp://pay, ftp://…) — same phishing class;
    // the scheme AND its payload go, like the http case above.
    .replace(/[a-z][a-z0-9+.-]*:\/\/\S+/gi, "")
    // Scheme-less domains ("go to evil.com/support") — the 2026-09-16
    // red-team corpus showed the scheme regexes alone leave these intact.
    .replace(/\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|app|co|edu|gov|info|xyz|me|tv|uk)\b(?:\/\S*)?/gi, "")
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
  "unauthorized",
  "entry_blob_invalid",
  "entry_payload_malformed",
  "feedback_blob_invalid",
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

/** Retry-After on a 429 is seconds (or an HTTP-date); it is untrusted input
 *  — clamp to a sane ceiling so a hostile server cannot park the queue for
 *  days. Returns undefined when absent or unparseable. */
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
}

async function request(
  method: string,
  path: string,
  body?: unknown,
  extraHeaders: Record<string, string> = {},
  opts: RequestOptions = {},
): Promise<any> {
  const base = await getBaseUrl();
  const token = await secureStore.getItem(TOKEN_KEY);
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
  if (response.status === 204) return null;
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
    const retryAfter =
      response.status === 429 && typeof response.headers?.get === "function"
        ? parseRetryAfter(response.headers.get("retry-after"))
        : undefined;
    throw new ApiError(
      response.status,
      detailToMessage((data as { detail?: unknown }).detail, response.status),
      sanitizeCode((data as { code?: unknown }).code),
      retryAfter,
    );
  }
  return data;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    /** Machine-readable v1 error code; undefined on legacy servers. */
    public code?: ApiErrorCode,
    /** Server-advised retry delay (429 Retry-After), clamped; else absent. */
    public retryAfterMs?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
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
    request("POST", `${API_PREFIX}/auth/login`, { username, verifier: authKeyB64 }, {}, { sensitive: true }),
  /** Server-side kill switch: invalidates every bearer token for the account. */
  logout: () => request("POST", `${API_PREFIX}/auth/logout`),

  createEntry: (clientEntryId: string, blobB64: string, entryDate: string) =>
    request("POST", `${API_PREFIX}/entries`, { client_entry_id: clientEntryId, blob: blobB64, entry_date: entryDate }),
  /** Paginates through every page (server caps pages at 500 entries).
   *  Offset pagination can drift under CONCURRENT inserts (a new entry
   *  shifts later rows down one page boundary): the consumer-side fix is
   *  the dedupe below — entries are append-mostly, so the residual risk is
   *  a missed just-inserted row, which the next incremental pull (since=)
   *  picks up. Full-history consumers should still key on client_entry_id. */
  listEntries: async (since?: string): Promise<ListedEntry[]> => {
    const all: ListedEntry[] = [];
    const seen = new Set<string>();
    const pageSize = 500;
    for (let page = 0; page < MAX_LIST_PAGES; page++) {
      const params = new URLSearchParams({ limit: String(pageSize), offset: String(page * pageSize) });
      if (since) params.set("since", since);
      const result = (await request("GET", `${API_PREFIX}/entries?${params.toString()}`)) as ListedEntry[];
      for (const entry of result) {
        if (seen.has(entry.client_entry_id)) continue; // page-boundary drift
        seen.add(entry.client_entry_id);
        all.push(entry);
      }
      if (result.length < pageSize) return all;
    }
    // A hostile or broken server can return full pages forever — abort
    // loudly instead of looping (and allocating) without bound.
    throw new ApiError(0, "server keeps returning full entry pages — aborting sync, contact support or check the server");
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

  /** 2026-09-16 (red-team finding F2): the data key is the whole journal.
   *  Ordinary requests may run over consented plain HTTP (BYO-server), but
   *  the KEY shipment refuses it outright — https or loopback only, no
   *  consent dialog can override that. */
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
