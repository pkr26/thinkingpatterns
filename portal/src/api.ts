/**
 * Portal API client. The token lives in memory only (the portal's whole
 * key material — derived keys included — never touches localStorage).
 *
 * Server URL: same-origin by default (the dev server proxies /api to the
 * backend); an explicit base may be configured in Settings-less v1 via
 * the login form's server field.
 */

const API_PREFIX = "/api/v1";

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
}

let session: Session | null = null;

export function setSession(token: string, baseUrl: string): void {
  session = { token, baseUrl };
  // A new session re-arms the 401 latch below: every sign-in gets its own
  // one-shot expiry fire, even without a page reload in between.
  unauthorizedFired = false;
}

export function clearSession(): void {
  session = null;
}

export function hasSession(): boolean {
  return session !== null;
}

function message(detail: unknown, status: number): string {
  if (typeof detail === "string" && detail.trim()) return detail.slice(0, 200);
  return `request failed (${status})`;
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

async function request<T>(method: string, path: string, body?: unknown, extraHeaders: Record<string, string> = {}): Promise<T> {
  if (!session) throw new ApiError(0, "not signed in");
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${session.token}`,
    ...extraHeaders,
  };
  let response: Response;
  try {
    response = await fetch(`${session.baseUrl}${API_PREFIX}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "server unreachable — check the server URL or your connection");
  }
  if (response.status === 401 && !unauthorizedFired) {
    unauthorizedFired = true;
    unauthorizedHandler?.();
  }
  if (response.status === 204) return null as T;
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

// --- unauthenticated auth flow (uses the same request core, no token) ------

async function authRequest<T>(baseUrl: string, method: string, path: string, body?: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${baseUrl}${API_PREFIX}${path}`, {
      method,
      headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
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

export const auth = {
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
  ) => authRequest<TokenResponse>(baseUrl, "POST", "/therapist/register", payload),
};

// --- authenticated therapist endpoints (backend schemas) ----------------------

export interface TherapistMe {
  username: string;
  display_name: string;
  wrap_pub_key: string;
  wrap_key_blob: string;
}

export interface Patient {
  user_id: string;
  username: string;
  status: string;
  granted_at: string;
  revoked_at: string | null;
  ephemeral_pub: string | null;
  wrapped_key: string | null;
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

export interface Note {
  id: string;
  client_note_id: string;
  pattern_pid: string | null;
  blob: string;
  created_at: string;
  updated_at: string;
}

export const api = {
  me: () => request<TherapistMe>("GET", "/therapist/me"),
  patients: () => request<Patient[]>("GET", "/therapist/patients"),
  patientInsights: (userId: string) =>
    request<InsightsSummary>("GET", `/therapist/patients/${userId}/insights`),
  patientEntries: (userId: string, params: { since?: string; until?: string; limit?: number; offset?: number } = {}) => {
    const search = new URLSearchParams();
    if (params.since) search.set("since", params.since);
    if (params.until) search.set("until", params.until);
    search.set("limit", String(params.limit ?? 500));
    if (params.offset) search.set("offset", String(params.offset));
    return request<PortalEntry[]>(
      "GET",
      `/therapist/patients/${userId}/entries?${search.toString()}`,
    );
  },
  notes: (userId: string) => request<Note[]>("GET", `/therapist/patients/${userId}/notes`),
  createNote: (userId: string, payload: { client_note_id: string; pattern_pid?: string | null; blob: string }) =>
    request<Note>("POST", `/therapist/patients/${userId}/notes`, payload),
  updateNote: (noteId: string, blob: string) =>
    request<Note>("PATCH", `/therapist/notes/${noteId}`, { blob }),
  deleteNote: (noteId: string) => request<null>("DELETE", `/therapist/notes/${noteId}`),
  newPairingCode: () => request<{ code: string; expires_in: number }>("POST", "/therapist/pairing-codes"),
};
