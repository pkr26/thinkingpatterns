/**
 * Web API client. The token lives in memory only (the app's whole key
 * material — derived keys included — never touches storage, WEB_PLAN D-4).
 *
 * Server URL: SAME-ORIGIN ONLY, by design — there is no configurable
 * server field and there must not be one. Deployment routes /api through
 * the app's TLS origin and development uses Vite's same-origin proxy. A
 * maintainer "restoring" a configurable server field would reopen the
 * verifier-collection vector: a user-typed HTTPS endpoint can be an
 * attacker's server that chooses the salt and harvests the derived
 * verifier for offline guessing.
 *
 * Request core (hardening identical to the portal's client): 15 s
 * deadline, credentials omitted, redirects refused, no-store, no
 * referrer, post-fetch origin re-check, session-scoped AbortController,
 * and a one-shot 401/410 expiry latch per session.
 */

import { currentOrigin } from "../platform";

const API_PREFIX = "/api/v1";

/** Request deadline: without one, a hung backend parks the UI forever on
 *  a fetch that will never answer. */
const REQUEST_TIMEOUT_MS = 15_000;

function isDevelopmentBuild(): boolean {
  return import.meta.env.DEV === true || import.meta.env.MODE === "test";
}

function isExplicitLoopback(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host === "::1";
}

export function normalizeApiBaseUrl(candidate: string): string {
  const trimmed = candidate.trim().replace(/\/+$/, "");
  if (trimmed === "") return "";
  try {
    const url = new URL(trimmed);
    const permittedProtocol = url.protocol === "https:"
      || (isDevelopmentBuild() && url.protocol === "http:" && isExplicitLoopback(url.hostname));
    // Credentials, query strings, and fragments do not belong in a stable
    // API base. A userinfo component is easy to misread in a login form
    // and has historically been used for URL spoofing.
    if (!permittedProtocol || url.username || url.password || url.search || url.hash) return "";
    return url.origin + url.pathname.replace(/\/+$/, "");
  } catch {
    return "";
  }
}

/** The one API base this client will ever use: the page's own origin. */
export function apiBaseUrl(): string {
  const normalized = normalizeApiBaseUrl(currentOrigin());
  if (!normalized) {
    throw new ApiError(0, "this app must be served over HTTPS (or a local development server)");
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

/** The complete backend error-code contract (README "API surface"), as the
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
  "entry_blob_invalid",
  "entry_payload_malformed",
  "totp_required",
  "totp_code_invalid",
  "internal_error",
  "service_unavailable",
  "bad_request",
] as const;
export type ApiErrorCode = (typeof API_ERROR_CODES)[number];

function sanitizeCode(code: unknown): ApiErrorCode | undefined {
  return typeof code === "string" && (API_ERROR_CODES as readonly string[]).includes(code)
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

export function setSession(token: string, userId: string, username: string): void {
  if (!token.trim()) throw new ApiError(0, "invalid empty session token");
  const baseUrl = apiBaseUrl();
  // A replacement session must not leave requests for the old account
  // alive in the background.
  clearSession();
  session = { token, userId, username, baseUrl, controller: new AbortController() };
  // A new session re-arms the expiry latch: every sign-in gets its own
  // one-shot fire, even without a page reload in between.
  sessionExpiredFired = false;
}

export function clearSession(): void {
  session?.controller.abort();
  session = null;
}

export function hasSession(): boolean {
  return session !== null;
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
  if (typeof detail === "string") return sanitizeDetail(detail) || `request failed (${status})`;
  if (Array.isArray(detail)) {
    const parts = detail.map((d) =>
      typeof d === "object" && d !== null && "msg" in d && typeof (d as { msg: unknown }).msg === "string"
        ? (d as { msg: string }).msg
        : "invalid field",
    );
    if (parts.length > 0) return sanitizeDetail(parts.join("; ")) || `request failed (${status})`;
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
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const abortForSessionEnd = (): void => controller.abort();
  if (sessionSignal?.aborted) controller.abort();
  else sessionSignal?.addEventListener("abort", abortForSessionEnd, { once: true });
  try {
    const response = await fetch(url, {
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
          throw new ApiError(0, "server redirected the request to a different origin");
        }
      } catch (err) {
        if (err instanceof ApiError) throw err;
        throw new ApiError(0, "server returned an invalid response origin");
      }
    }
    return response;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if (err instanceof Error && err.name === "AbortError") {
      if (sessionSignal?.aborted) throw new ApiError(0, "session ended");
      throw new ApiError(0, `request timed out after ${REQUEST_TIMEOUT_MS / 1000}s`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
    sessionSignal?.removeEventListener("abort", abortForSessionEnd);
  }
}

/** Session-expiry hook: any 401 (or 410 account death) fires this ONCE per
 *  session (setSession re-arms it) — App funnels the whole UI to an
 *  explicit sign-in state instead of a cryptic banner while keys sit in
 *  memory. The error is handed over so the lock screen can say WHAT
 *  happened (expired vs rotated vs deleted — WEB_PLAN D-8). */
let sessionExpiredHandler: ((err: ApiError) => void) | null = null;
let sessionExpiredFired = false;
export function setSessionExpiredHandler(fn: ((err: ApiError) => void) | null): void {
  sessionExpiredHandler = fn;
  sessionExpiredFired = false;
}

interface ApiResponse<T> {
  data: T;
  headers: Headers;
}

function isSessionDeath(status: number, code: ApiErrorCode | undefined): boolean {
  if (status === 401) return true;
  // 410 account_deleted: the account was deleted from another device.
  return status === 410 && (code === "account_deleted" || code === "gone");
}

async function requestWithResponse<T>(
  method: string,
  path: string,
  body?: unknown,
  extraHeaders: Record<string, string> = {},
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
      { method, headers, body: body === undefined ? undefined : JSON.stringify(body) },
      activeSession.baseUrl,
      activeSession.controller.signal,
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
  const data = safeJson(raw) as { detail?: unknown; code?: unknown };
  const code = sanitizeCode(data.code);
  if (isSessionDeath(response.status, code) && !sessionExpiredFired) {
    sessionExpiredFired = true;
    sessionExpiredHandler?.(new ApiError(response.status, message(data.detail, response.status), code));
  }
  if (response.status === 204) return { data: null as T, headers: response.headers };
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
    if (typeof parsed === "object" && parsed !== null) return parsed as Record<string, unknown>;
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
): Promise<T> {
  return (await requestWithResponse<T>(method, path, body, extraHeaders)).data;
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
      { method, headers: { "Content-Type": "application/json", ...extraHeaders }, body: body === undefined ? undefined : JSON.stringify(body) },
      baseUrl,
    );
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(0, "server unreachable — check your connection");
  }
  const data = (await response.json().catch(() => ({}))) as { detail?: unknown; code?: unknown };
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
}

export interface ServerMeta {
  version: string;
  api_version: string;
  unlock_days: number;
  llm_available: boolean;
  llm_provider_name: string | null;
  llm_data_retention: string | null;
  sharing_available: boolean;
  sharing_disclosure_version: string;
}

export const auth = {
  meta: () => authRequest<ServerMeta>("GET", "/meta"),
  saltFor: (username: string) => authRequest<{ salt: string }>("POST", "/auth/salt", { username }),
  login: (username: string, verifierB64: string) =>
    authRequest<TokenResponse>("POST", "/auth/login", { username, verifier: verifierB64 }),
  register: (username: string, saltB64: string, verifierB64: string) =>
    authRequest<TokenResponse>("POST", "/auth/register", { username, salt: saltB64, verifier: verifierB64 }),
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
      const getPage = async (pageOffset: number): Promise<ListedEntriesPage> => {
        const result = await api.listEntriesPage({
          since,
          limit: pageSize,
          offset: pageOffset,
          pageBytes: ENTRY_PAGE_BYTES,
          ...(revisionMode === "snapshot" && revision !== null ? { expectedRevision: revision } : {}),
        });
        const receivedRevision = result.revision ?? null;
        if (revisionMode === "unknown") {
          revisionMode = receivedRevision === null ? "legacy" : "snapshot";
          revision = receivedRevision;
        } else if (
          (revisionMode === "snapshot" && receivedRevision !== revision)
          || (revisionMode === "legacy" && receivedRevision !== null)
        ) {
          // A load-balanced deployment changed protocol modes during one
          // walk. Restart instead of mixing unpinned and pinned pages.
          throw new ApiError(409, "the entries snapshot changed mid-walk — restarting", "collection_changed");
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
      throw new ApiError(0, "server keeps returning entry continuations — aborting sync");
    } catch (err) {
      if (err instanceof ApiError && err.status === 409 && attempt < MAX_LIST_SNAPSHOT_RESTARTS) continue;
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
    throw new ApiError(0, `server returned an invalid ${resource} continuation`);
  }
  const nextOffset = Number(header);
  // Offset pagination must advance exactly past the materialized rows —
  // this catches a malformed/proxy-injected cursor before it can loop or
  // skip rows, including "more after an empty page".
  if (!Number.isSafeInteger(nextOffset) || rowCount === 0 || nextOffset !== offset + rowCount) {
    throw new ApiError(0, `server returned an invalid ${resource} continuation`);
  }
  return nextOffset;
}

/** The server's snapshot counter is a signed 64-bit integer. Keep it as its
 *  canonical decimal wire representation: a JavaScript number would lose
 *  the low bits for most valid server values. */
const MAX_SIGNED_64_REVISION = "9223372036854775807";

function isCanonicalRevision(revision: string): boolean {
  return /^(?:0|[1-9][0-9]{0,18})$/.test(revision)
    && (revision.length < MAX_SIGNED_64_REVISION.length
      || (revision.length === MAX_SIGNED_64_REVISION.length && revision <= MAX_SIGNED_64_REVISION));
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
    throw new ApiError(0, `server returned an invalid ${resource} snapshot revision`);
  }
  if (expectedRevision !== undefined && header !== expectedRevision) {
    throw new ApiError(0, `server returned a changed ${resource} snapshot revision`);
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
export const SHARING_DISCLOSURE_VERSION = "v2";
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
}

export interface PairingLookup {
  therapist_id: string;
  display_name: string;
  wrap_pub_key: string;
}

// --- the authenticated endpoint surface -------------------------------------------

export const api = {
  meta: () => request<ServerMeta>("GET", "/meta"),
  /** Logout deliberately does NOT ride the session's AbortController: the
   *  button fires this and then synchronously calls clearSession(), whose
   *  abort would cancel the very epoch bump (account-wide sign-out) the
   *  request exists to perform (audit 2026-09-25). It keeps every other
   *  hardening (deadline, no credentials, redirect refusal, origin recheck)
   *  and uses the token captured at call time. */
  logout: async (): Promise<null> => {
    const activeSession = session;
    if (!activeSession) throw new ApiError(0, "not signed in");
    const response = await fetchWithTimeout(
      `${activeSession.baseUrl}${API_PREFIX}/auth/logout`,
      { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${activeSession.token}` } },
      activeSession.baseUrl,
    );
    if (response.status === 204) return null;
    const data = (await response.json().catch(() => ({}))) as { detail?: unknown; code?: unknown };
    if (!response.ok) {
      throw new ApiError(response.status, message(data.detail, response.status), sanitizeCode(data.code));
    }
    return null;
  },

  createEntry: (clientEntryId: string, blobB64: string, entryDate: string, contentVersion?: number) => {
    if (!ENTRY_ID_PATTERN.test(clientEntryId)) throw new ApiError(0, "invalid entry id — refusing the request");
    return request<{ id: string }>("POST", "/entries", {
      client_entry_id: clientEntryId,
      blob: blobB64,
      entry_date: entryDate,
      ...(contentVersion !== undefined ? { content_version: contentVersion } : {}),
    });
  },
  getEntry: (clientEntryId: string) => {
    if (!ENTRY_ID_PATTERN.test(clientEntryId)) throw new ApiError(0, "invalid entry id — refusing the request");
    return request<ListedEntry>("GET", `/entries/${encodeURIComponent(clientEntryId)}`);
  },
  updateEntry: (clientEntryId: string, blobB64: string, entryDate: string, contentVersion?: number) => {
    if (!ENTRY_ID_PATTERN.test(clientEntryId)) throw new ApiError(0, "invalid entry id — refusing the request");
    return request<{ id: string }>(
      "PUT",
      `/entries/${encodeURIComponent(clientEntryId)}`,
      { blob: blobB64, entry_date: entryDate, ...(contentVersion !== undefined ? { content_version: contentVersion } : {}) },
    );
  },
  deleteEntry: (clientEntryId: string) => {
    if (!ENTRY_ID_PATTERN.test(clientEntryId)) throw new ApiError(0, "invalid entry id — refusing the request");
    return request<null>("DELETE", `/entries/${encodeURIComponent(clientEntryId)}`);
  },
  listEntriesPage: async (options: ListEntriesPageOptions = {}): Promise<ListedEntriesPage> => {
    const limit = options.limit ?? ENTRY_LIST_PAGE_SIZE;
    const offset = options.offset ?? 0;
    const pageBytes = options.pageBytes ?? ENTRY_PAGE_BYTES;
    if (
      !Number.isInteger(limit) || limit < 1 || limit > ENTRY_PAGE_LIMIT
      || !Number.isSafeInteger(offset) || offset < 0
      || !Number.isInteger(pageBytes) || pageBytes < 1 || pageBytes > ENTRY_PAGE_BYTES
      || (options.expectedRevision !== undefined && !isCanonicalRevision(options.expectedRevision))
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
    const response = await requestWithResponse<ListedEntry[]>("GET", `/entries?${params.toString()}`);
    if (!Array.isArray(response.data)) throw new ApiError(0, "server returned an invalid entries page");
    return {
      entries: response.data,
      nextOffset: validatedNextOffset(response.headers.get("X-Next-Offset"), offset, response.data.length, "entries"),
      revision: validatedRevision(response.headers.get("X-Entries-Revision"), options.expectedRevision, "entries"),
    };
  },

  createMeasure: (clientMeasureId: string, blobB64: string, measureDate: string) =>
    request<{ id: string }>("POST", "/measures", {
      client_measure_id: clientMeasureId,
      blob: blobB64,
      measure_date: measureDate,
    }),
  listMeasuresPage: async (params: { offset?: number; expectedRevision?: string } = {}): Promise<ListedMeasuresPage> => {
    const offset = params.offset ?? 0;
    if (!Number.isSafeInteger(offset) || offset < 0) throw new ApiError(0, "invalid measure page request");
    if (params.expectedRevision !== undefined && !isCanonicalRevision(params.expectedRevision)) {
      throw new ApiError(0, "invalid measure page request");
    }
    const search = new URLSearchParams({ limit: "100", page_bytes: String(ENTRY_PAGE_BYTES) });
    if (offset > 0) search.set("offset", String(offset));
    if (params.expectedRevision !== undefined) search.set("expected_revision", params.expectedRevision);
    const response = await requestWithResponse<ListedMeasure[]>("GET", `/measures?${search.toString()}`);
    if (!Array.isArray(response.data)) throw new ApiError(0, "server returned an invalid measures page");
    return {
      measures: response.data,
      nextOffset: validatedNextOffset(response.headers.get("X-Next-Offset"), offset, response.data.length, "measures"),
      revision: validatedRevision(response.headers.get("X-Measures-Revision"), params.expectedRevision, "measures"),
    };
  },

  openProcessingSession: (dataKeyB64: string) =>
    request<{ session_token: string; expires_in: number }>("POST", "/processing/sessions", { data_key: dataKeyB64 }),
  recompute: (processingToken: string, feedbackBlob?: string) =>
    request<{ phase: string; active_days?: number; streak?: number; days_remaining?: number }>(
      "POST",
      "/insights/recompute",
      feedbackBlob ? ({ feedback_blob: feedbackBlob } as Record<string, unknown>) : undefined,
      { "X-Processing-Token": processingToken },
    ),
  insights: () =>
    request<{ phase: string; active_days: number; streak: number; days_remaining: number; blob: string | null; state_seq?: number }>(
      "GET",
      "/insights",
    ),
  questionToday: () => request<{ for_date: string; blob: string }>("GET", "/questions/today"),

  /** The streamed ciphertext export — returns the RAW response (P7 turns it
   *  into a download); nothing about the request core is bypassed. */
  exportAccountRaw: async (): Promise<Response> => {
    const activeSession = session;
    if (!activeSession) throw new ApiError(0, "not signed in");
    return fetchWithTimeout(
      `${activeSession.baseUrl}${API_PREFIX}/account/export`,
      {
        method: "GET",
        headers: { Authorization: `Bearer ${activeSession.token}` },
        credentials: "omit",
      },
      activeSession.baseUrl,
      activeSession.controller.signal,
    );
  },
  /** Requires the password-derived verifier: a stolen token cannot erase
   *  data. The verifier travels in the X-Account-Verifier header, never the URL. */
  deleteAccount: (verifierB64: string) =>
    request<null>("DELETE", "/account", undefined, { "X-Account-Verifier": verifierB64 }),
  getLlmConsent: () => request<{ enabled: boolean; provider_name?: string | null }>("GET", "/account/llm-consent"),
  setLlmConsent: (enabled: boolean, verifierB64: string) =>
    request<{ enabled: boolean }>("PUT", "/account/llm-consent", { enabled, verifier: verifierB64 }),
  accessLogPage: async (cursor?: string): Promise<{ rows: { at: string; action: string; actor: string }[]; nextCursor: string | null }> => {
    const response = await requestWithResponse<{ at: string; action: string; actor: string }[]>(
      "GET",
      `/account/access-log${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""}`,
    );
    const rows = Array.isArray(response.data) ? response.data : [];
    const next = response.headers.get("X-Next-Cursor");
    return { rows, nextCursor: next && next.trim() ? next : null };
  },

  rekeyStoredData: (oldProcessingToken: string, newProcessingToken: string, verifierB64: string) =>
    request<null>(
      "POST",
      "/processing/rekey",
      undefined,
      {
        "X-Processing-Token": oldProcessingToken,
        "X-New-Processing-Token": newProcessingToken,
        "X-Account-Verifier": verifierB64,
      },
    ),
  rotateCredential: (oldVerifierB64: string, newSaltB64: string, newVerifierB64: string) =>
    request<null>("PUT", "/account/credential", {
      verifier: oldVerifierB64,
      new_salt: newSaltB64,
      new_verifier: newVerifierB64,
    }),

  pairingLookup: (code: string) => request<PairingLookup>("POST", "/consents/pairing/lookup", { code }),
  grantConsent: (code: string, ephemeralPubB64: string, wrappedKeyB64: string, verifierB64: string) =>
    request<ListedConsent>(
      "POST",
      "/consents",
      { code, ephemeral_pub: ephemeralPubB64, wrapped_key: wrappedKeyB64, disclosure: SHARING_DISCLOSURE_VERSION },
      { "X-Account-Verifier": verifierB64 },
    ),
  listConsents: () => request<ListedConsent[]>("GET", "/consents"),
  rewrapConsent: (consentId: string, ephemeralPubB64: string, wrappedKeyB64: string, verifierB64: string) => {
    if (!CONSENT_ID_PATTERN.test(consentId)) throw new ApiError(0, "invalid consent id — refusing the request");
    return request<null>(
      "PUT",
      `/consents/${consentId}/rewrap`,
      { ephemeral_pub: ephemeralPubB64, wrapped_key: wrappedKeyB64 },
      { "X-Account-Verifier": verifierB64 },
    );
  },
  revokeConsent: (consentId: string, verifierB64: string) => {
    if (!CONSENT_ID_PATTERN.test(consentId)) throw new ApiError(0, "invalid consent id — refusing the request");
    return request<null>("DELETE", `/consents/${consentId}`, undefined, { "X-Account-Verifier": verifierB64 });
  },
};
