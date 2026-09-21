/**
 * Portal API client. The token lives in memory only (the portal's whole
 * key material — derived keys included — never touches localStorage).
 *
 * Server URL: SAME-ORIGIN ONLY, by design — there is no configurable
 * server field and there must not be one (see LoginView: the login form
 * renders the portal's own origin and refuses to change it). Deployment
 * routes /api through the portal's TLS origin and development uses
 * Vite's same-origin proxy. A maintainer "restoring" a configurable
 * server field would reopen the verifier-collection vector: a
 * user-typed HTTPS endpoint can be an attacker's server that chooses
 * the salt and harvests the derived verifier (or an enrollment token)
 * for offline guessing.
 */

const API_PREFIX = "/api/v1";

/** Request deadline (2026-09-17 audit): without one, a hung backend parks
 * the UI forever on a fetch that will never answer — the mobile client has
 * had the same 15 s cap since v1. */
const REQUEST_TIMEOUT_MS = 15_000;

/**
 * A portal token is deliberately usable only against an HTTPS origin.  The
 * sole exception is an explicit loopback server while running a development
 * or test build; accepting arbitrary `http:` here would hand a bearer token
 * to any network observer on a clinic Wi-Fi network.
 *
 * Keep this policy next to the fetch implementation rather than solely in
 * LoginView.  That way a future caller cannot bypass the form and install a
 * session for an unsafe origin programmatically.
 */
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
    // API base.  In particular, a userinfo component is easy to misread in a
    // login form and has historically been used for URL spoofing.
    if (!permittedProtocol || url.username || url.password || url.search || url.hash) return "";
    return url.origin + url.pathname.replace(/\/+$/, "");
  } catch {
    return "";
  }
}

function requireSafeBaseUrl(baseUrl: string): string {
  const normalized = normalizeApiBaseUrl(baseUrl);
  if (!normalized || normalized !== baseUrl) {
    throw new ApiError(0, "use an HTTPS server URL (or an explicit local development server)");
  }
  return normalized;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public code?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

interface Session {
  token: string;
  baseUrl: string;
  /** Cancels all in-flight authenticated fetches at logout / expiry. */
  controller: AbortController;
}

let session: Session | null = null;

export function setSession(token: string, baseUrl: string): void {
  if (!token.trim()) throw new ApiError(0, "invalid empty session token");
  const safeBaseUrl = requireSafeBaseUrl(baseUrl);
  // A replacement session must not leave requests for the old clinician
  // account alive in the background.
  clearSession();
  session = { token, baseUrl: safeBaseUrl, controller: new AbortController() };
  // A new session re-arms the 401 latch below: every sign-in gets its own
  // one-shot expiry fire, even without a page reload in between.
  unauthorizedFired = false;
}

export function clearSession(): void {
  session?.controller.abort();
  session = null;
}

export function hasSession(): boolean {
  return session !== null;
}

function message(detail: unknown, status: number): string {
  if (typeof detail === "string" && detail.trim()) return detail.slice(0, 200);
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
      // cookies.  Refusing redirects means a 30x cannot forward that bearer
      // token to another origin before this code gets to inspect it.
      credentials: "omit",
      redirect: "error",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      signal: controller.signal,
    });
    // Browsers normally reject redirect:error before exposing a response.
    // This explicit check also protects alternate fetch implementations and
    // makes the invariant visible in tests.
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

/** Session-expiry hook (2026-09-17): any 401 fires this ONCE per session
 *  (setSession re-arms it) — App swaps the whole UI to an explicit
 *  "session expired" sign-in instead of a cryptic banner while keys sit
 *  in memory. */
let unauthorizedHandler: (() => void) | null = null;
let unauthorizedFired = false;
export function setUnauthorizedHandler(fn: (() => void) | null): void {
  unauthorizedHandler = fn;
  unauthorizedFired = false;
}

interface ApiResponse<T> {
  data: T;
  headers: Headers;
}

/** Authenticated request retaining response headers for the few endpoints
 * whose pagination contract is header-based.  Keeping parsing and status
 * handling centralized prevents a header-aware caller from accidentally
 * bypassing the session/redirect protections above. */
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
    response = await fetchWithTimeout(`${activeSession.baseUrl}${API_PREFIX}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    }, activeSession.baseUrl, activeSession.controller.signal);
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(0, "server unreachable — check the server URL or your connection");
  }
  // A fetch implementation can resolve despite an abort race.  Do not parse
  // or return protected content once logout / expiry has replaced the
  // session that initiated this request.
  if (session !== activeSession) throw new ApiError(0, "session ended");
  if (response.status === 401 && !unauthorizedFired) {
    unauthorizedFired = true;
    unauthorizedHandler?.();
  }
  if (response.status === 204) return { data: null as T, headers: response.headers };
  const data = (await response.json().catch(() => ({}))) as { detail?: unknown; code?: unknown };
  if (!response.ok) {
    throw new ApiError(
      response.status,
      message(data.detail, response.status),
      typeof data.code === "string" ? data.code : undefined,
    );
  }
  return { data: data as T, headers: response.headers };
}

async function request<T>(method: string, path: string, body?: unknown, extraHeaders: Record<string, string> = {}): Promise<T> {
  return (await requestWithResponse<T>(method, path, body, extraHeaders)).data;
}

// --- unauthenticated auth flow (uses the same request core, no token) ------

async function authRequest<T>(
  baseUrl: string,
  method: string,
  path: string,
  body?: unknown,
  extraHeaders: Record<string, string> = {},
): Promise<T> {
  const safeBaseUrl = requireSafeBaseUrl(baseUrl);
  let response: Response;
  try {
    response = await fetchWithTimeout(`${safeBaseUrl}${API_PREFIX}${path}`, {
      method,
      headers: { "Content-Type": "application/json", ...extraHeaders },
      body: body === undefined ? undefined : JSON.stringify(body),
    }, safeBaseUrl);
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(0, "server unreachable — check the server URL or your connection");
  }
  const data = (await response.json().catch(() => ({}))) as { detail?: unknown; code?: unknown };
  if (!response.ok) {
    throw new ApiError(
      response.status,
      message(data.detail, response.status),
      typeof data.code === "string" ? data.code : undefined,
    );
  }
  return data as T;
}

export interface TokenResponse {
  token: string;
  user_id: string;
  expires_in: number;
  role: string;
}

/** Non-personal deployment policy advertised by GET /meta. */
export interface ServerMeta {
  sharing_available: boolean;
}

export const auth = {
  meta: (baseUrl: string) => authRequest<ServerMeta>(baseUrl, "GET", "/meta"),
  saltFor: (baseUrl: string, username: string) =>
    authRequest<{ salt: string }>(baseUrl, "POST", "/auth/salt", { username }),
  login: (baseUrl: string, username: string, verifierB64: string) =>
    authRequest<TokenResponse>(baseUrl, "POST", "/auth/login", { username, verifier: verifierB64 }),
  registerTherapist: (
    baseUrl: string,
    payload: {
      username: string;
      salt: string;
      verifier: string;
      display_name: string;
      wrap_pub_key: string;
      wrap_key_blob: string;
    },
    enrollmentToken?: string,
  ) => authRequest<TokenResponse>(
    baseUrl,
    "POST",
    "/therapist/register",
    payload,
    enrollmentToken?.trim()
      ? { "X-Therapist-Enrollment-Token": enrollmentToken.trim() }
      : {},
  ),
};

// --- authenticated therapist endpoints (backend schemas) ----------------------

export interface TherapistMe {
  username: string;
  display_name: string;
  wrap_pub_key: string;
  wrap_key_blob: string;
}

/** One row of the therapist's own action history (2026-09-21 audit B-4):
 *  every portal read/write, newest first. `patient_name` is null on
 *  self-lifecycle rows (e.g. wrap-key rotation). */
export interface AccessLogRow {
  at: string;
  action: string;
  patient_name: string | null;
}

export interface Patient {
  user_id: string;
  username: string;
  status: string;
  granted_at: string;
  revoked_at: string | null;
  ephemeral_pub: string | null;
  wrapped_key: string | null;
  /** Caseload summary (2026-09-19): ECIES-wrapped to this therapist at the
   *  patient's last recompute; null until that first recompute and after a
   *  revoke. Decrypted locally with decryptCaseloadSummary. */
  summary_blob?: string | null;
  summary_eph_pub?: string | null;
  summary_updated_at?: string | null;
}

export interface InsightsSummary {
  phase: string;
  active_days: number;
  streak: number;
  days_remaining: number;
  blob: string | null;
}

export interface PortalEntry {
  id: string;
  client_entry_id: string;
  blob: string;
  entry_date: string;
  received_at: string;
}

/** The backend caps a therapist evidence response at 25 rows and 2 MiB of
 * raw ciphertext.  Never expose a caller-controlled larger page request. */
export const THERAPIST_ENTRY_PAGE_SIZE = 25;
export const THERAPIST_ENTRY_PAGE_BYTES = 2 * 1024 * 1024;

export interface PortalMeasure {
  id: string;
  client_measure_id: string;
  blob: string;
  measure_date: string;
  received_at: string;
}

/** One measures page request (audit L-76 / M-4, 2026-09-20): the backend
 *  serves this many rows per request at most (deterministic order
 *  measure_date DESC, received_at DESC, id DESC) and accepts limit/offset
 *  continuation.  100 stays well under the server cap on every backend
 *  generation, keeping each response small while the caller pages. */
export const THERAPIST_MEASURE_PAGE_SIZE = 100;

export interface PatientEntriesPage {
  entries: PortalEntry[];
  /** Absent means this filtered result set is complete. */
  nextOffset: number | null;
  /**
   * The immutable snapshot revision advertised by a revision-aware backend.
   * Undefined is deliberate compatibility mode for an older headerless
   * backend; callers must then retain the bounded offset fallback.
   */
  revision?: string;
}

function validatedNextOffset(
  header: string | null,
  offset: number,
  rowCount: number,
  pageSize: number,
  resource: string,
): number | null {
  if (header === null) {
    // Compatibility with an older backend that ignores `page_bytes` and has
    // no continuation header: a full requested page is the one unambiguous
    // signal that another offset may exist. A short page remains terminal.
    // The caller's finite page cap bounds the one harmless extra request
    // when the total is an exact multiple of pageSize.
    return rowCount === pageSize ? offset + rowCount : null;
  }
  // Decimal-only parsing avoids Number("1e3"), signs, whitespace, and
  // precision loss quietly changing pagination state.
  if (!/^(?:0|[1-9][0-9]*)$/.test(header)) {
    throw new ApiError(0, `server returned an invalid ${resource} continuation`);
  }
  const nextOffset = Number(header);
  // Offset pagination must advance exactly past the materialized rows. This
  // catches a malformed/proxy-injected cursor before it can loop or skip
  // evidence, including the impossible "more after an empty page" case.
  if (
    !Number.isSafeInteger(nextOffset)
    || rowCount === 0
    || nextOffset !== offset + rowCount
  ) {
    throw new ApiError(0, `server returned an invalid ${resource} continuation`);
  }
  return nextOffset;
}

/** The server's snapshot counter is a signed 64-bit integer. Keep it as its
 * canonical decimal wire representation: a JavaScript number would lose the
 * low bits for most valid server values, and then bind a continuation to the
 * wrong snapshot. */
const MAX_SIGNED_64_REVISION = "9223372036854775807";

function isCanonicalRevision(revision: string): boolean {
  return /^(?:0|[1-9][0-9]{0,18})$/.test(revision)
    && (revision.length < MAX_SIGNED_64_REVISION.length
      || (revision.length === MAX_SIGNED_64_REVISION.length && revision <= MAX_SIGNED_64_REVISION));
}

/** Parse the optional collection snapshot token without ever allowing an
 * arbitrary response header to become a continuation query value. */
function validatedRevision(
  header: string | null,
  expectedRevision: string | undefined,
  resource: string,
): string | undefined {
  if (header === null) {
    // A headerless server predates snapshots. It is safe to use its legacy
    // bounded pagination only before a snapshot has been established; once
    // a continuation carries a revision, silently dropping it would reopen
    // cross-page drift.
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

function assertExpectedRevision(revision: string | undefined, resource: string): void {
  if (revision !== undefined && !isCanonicalRevision(revision)) {
    throw new ApiError(0, `invalid ${resource} snapshot revision`);
  }
}

export interface Note {
  id: string;
  client_note_id: string;
  pattern_pid: string | null;
  blob: string;
  created_at: string;
  updated_at: string;
}

/** One superseded revision of a note (P3, 2026-09-21): the prior blob
 *  (same AAD as the live note) and when it was superseded. */
export interface NoteRevision {
  id: string;
  blob: string;
  created_at: string;
}

/** Notes have a larger item-count bound than evidence pages, but the server
 * still byte-truncates at 2 MiB and advertises continuation explicitly. */
export const THERAPIST_NOTE_PAGE_SIZE = 100;
export const THERAPIST_NOTE_PAGE_BYTES = 2 * 1024 * 1024;

export interface PatientNotesPage {
  notes: Note[];
  /** Absent means this therapist-private chart is complete. */
  nextOffset: number | null;
  /** Undefined when the connected backend predates snapshot pagination. */
  revision?: string;
}

export const api = {
  me: () => request<TherapistMe>("GET", "/therapist/me"),
  /** The newest 100 of this therapist's own audited actions (B-4). */
  accessLog: () => request<AccessLogRow[]>("GET", "/therapist/access-log?limit=100"),
  patients: () => request<Patient[]>("GET", "/therapist/patients"),
  patientInsights: (userId: string) =>
    request<InsightsSummary>("GET", `/therapist/patients/${encodeURIComponent(userId)}/insights`),
  patientMeasures: async (
    userId: string,
    params: { offset?: number; limit?: number } = {},
  ): Promise<PortalMeasure[]> => {
    const offset = params.offset ?? 0;
    if (!Number.isSafeInteger(offset) || offset < 0) {
      throw new ApiError(0, "invalid measure page offset");
    }
    if (params.limit !== undefined && (!Number.isSafeInteger(params.limit) || params.limit < 1)) {
      throw new ApiError(0, "invalid measure page limit");
    }
    const search = new URLSearchParams();
    if (params.limit !== undefined) search.set("limit", String(params.limit));
    // offset=0 is the default; omitting it keeps older backends (which
    // reject unknown query params less gracefully) on their plain path.
    if (offset > 0) search.set("offset", String(offset));
    const rows = await request<PortalMeasure[]>(
      "GET",
      `/therapist/patients/${encodeURIComponent(userId)}/measures${search.size > 0 ? `?${search.toString()}` : ""}`,
    );
    if (!Array.isArray(rows)) {
      throw new ApiError(0, "server returned an invalid measures page");
    }
    return rows;
  },
  patientEntries: async (
    userId: string,
    params: { since?: string; until?: string; offset?: number; expectedRevision?: string } = {},
  ): Promise<PatientEntriesPage> => {
    const offset = params.offset ?? 0;
    if (!Number.isSafeInteger(offset) || offset < 0) {
      throw new ApiError(0, "invalid evidence page offset");
    }
    assertExpectedRevision(params.expectedRevision, "evidence");
    const search = new URLSearchParams();
    if (params.since) search.set("since", params.since);
    if (params.until) search.set("until", params.until);
    search.set("limit", String(THERAPIST_ENTRY_PAGE_SIZE));
    // Opt in explicitly so an older portal cannot mistake a byte-truncated
    // response for the end of its evidence window.
    search.set("page_bytes", String(THERAPIST_ENTRY_PAGE_BYTES));
    if (offset > 0) search.set("offset", String(offset));
    if (params.expectedRevision !== undefined) {
      search.set("expected_revision", params.expectedRevision);
    }
    const response = await requestWithResponse<PortalEntry[]>(
      "GET",
      `/therapist/patients/${encodeURIComponent(userId)}/entries?${search.toString()}`,
    );
    if (!Array.isArray(response.data) || response.data.length > THERAPIST_ENTRY_PAGE_SIZE) {
      throw new ApiError(0, "server returned an invalid evidence page");
    }
    return {
      entries: response.data,
      nextOffset: validatedNextOffset(
        response.headers.get("X-Next-Offset"),
        offset,
        response.data.length,
        THERAPIST_ENTRY_PAGE_SIZE,
        "evidence",
      ),
      revision: validatedRevision(
        response.headers.get("X-Entries-Revision"),
        params.expectedRevision,
        "evidence",
      ),
    };
  },
  notes: async (
    userId: string,
    params: { offset?: number; expectedRevision?: string } = {},
  ): Promise<PatientNotesPage> => {
    const offset = params.offset ?? 0;
    if (!Number.isSafeInteger(offset) || offset < 0) {
      throw new ApiError(0, "invalid note page offset");
    }
    assertExpectedRevision(params.expectedRevision, "note");
    const search = new URLSearchParams();
    search.set("limit", String(THERAPIST_NOTE_PAGE_SIZE));
    // Explicitly opt into a byte-short page. Older portals that do not know
    // X-Next-Offset receive a clear 413 rather than silently losing notes.
    search.set("page_bytes", String(THERAPIST_NOTE_PAGE_BYTES));
    if (offset > 0) search.set("offset", String(offset));
    if (params.expectedRevision !== undefined) {
      search.set("expected_revision", params.expectedRevision);
    }
    const response = await requestWithResponse<Note[]>(
      "GET",
      `/therapist/patients/${encodeURIComponent(userId)}/notes?${search.toString()}`,
    );
    if (!Array.isArray(response.data) || response.data.length > THERAPIST_NOTE_PAGE_SIZE) {
      throw new ApiError(0, "server returned an invalid note page");
    }
    return {
      notes: response.data,
      nextOffset: validatedNextOffset(
        response.headers.get("X-Next-Offset"),
        offset,
        response.data.length,
        THERAPIST_NOTE_PAGE_SIZE,
        "note",
      ),
      revision: validatedRevision(
        response.headers.get("X-Notes-Revision"),
        params.expectedRevision,
        "note",
      ),
    };
  },
  createNote: (userId: string, payload: { client_note_id: string; pattern_pid?: string | null; blob: string }) =>
    request<Note>("POST", `/therapist/patients/${encodeURIComponent(userId)}/notes`, payload),
  noteRevisions: (noteId: string) =>
    request<NoteRevision[]>("GET", `/therapist/notes/${encodeURIComponent(noteId)}/revisions`),
  updateNote: (noteId: string, blob: string) =>
    request<Note>("PATCH", `/therapist/notes/${encodeURIComponent(noteId)}`, { blob }),
  deleteNote: (noteId: string) => request<null>("DELETE", `/therapist/notes/${encodeURIComponent(noteId)}`),
  newPairingCode: () => request<{ code: string; expires_in: number }>("POST", "/therapist/pairing-codes"),
};
