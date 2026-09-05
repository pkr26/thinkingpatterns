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
/** Entry ids this client generates are [A-Za-z0-9-]; anything else in this
 *  position is at-rest tampering and must never reach the URL path. */
const ENTRY_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

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
 *  recompute stamps, mood logs, queue quarantine. All of it belongs to
 *  the origin it was created against. */
function isOriginBoundKey(key: string): boolean {
  return (
    key.startsWith("@mindpattern/salt_") ||
    key.startsWith("@mindpattern/unlockproof_") ||
    key.startsWith("@mindpattern/last_recompute_") ||
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
    if (parts.length > 0) return sanitizeDetail(parts.join("; ")) || `request failed (${status})`;
  }
  return `request failed (${status})`;
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
      if (err instanceof ApiError) throw err;
      // An unparseable final URL degrades to the same refusal.
      throw new ApiError(0, "server redirected the request off the configured origin — check your server URL");
    }
  }
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new ApiError(response.status, detailToMessage((data as { detail?: unknown }).detail, response.status));
  }
  return data;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
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

  meta: () => request("GET", "/api/meta"),

  register: (username: string, saltB64: string, authKeyB64: string) =>
    request("POST", "/api/auth/register", { username, salt: saltB64, verifier: authKeyB64 }, {}, { sensitive: true }),
  // POST body, never a URL path: usernames must not land in proxy access logs.
  saltFor: (username: string) => request("POST", "/api/auth/salt", { username }),
  cacheSalt: async (username: string, saltB64: string) => {
    // Bind the salt to the origin it was served from: an offline unlock
    // under server B must never derive keys with server A's salt.
    const record = JSON.stringify({ o: await getBaseUrl(), s: saltB64 });
    await AsyncStorage.setItem(saltKey(username), record);
  },
  /** The last server-known salt for this username FROM THE CURRENT SERVER,
   *  or null. Enables offline vault unlock without cross-origin replay. */
  getCachedSalt: async (username: string) => {
    const raw = await AsyncStorage.getItem(saltKey(username));
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw) as { o?: unknown; s?: unknown };
      if (typeof parsed.o !== "string" || typeof parsed.s !== "string") return null;
      return parsed.o === (await getBaseUrl()) ? parsed.s : null;
    } catch {
      return null; // legacy/corrupt record: refuse rather than guess
    }
  },
  clearCachedSalt: async (username: string) => {
    await AsyncStorage.removeItem(saltKey(username));
  },
  login: (username: string, authKeyB64: string) =>
    request("POST", "/api/auth/login", { username, verifier: authKeyB64 }, {}, { sensitive: true }),
  /** Server-side kill switch: invalidates every bearer token for the account. */
  logout: () => request("POST", "/api/auth/logout"),

  createEntry: (clientEntryId: string, blobB64: string, entryDate: string) =>
    request("POST", "/api/entries", { client_entry_id: clientEntryId, blob: blobB64, entry_date: entryDate }),
  /** Paginates through every page (server caps pages at 500 entries). */
  listEntries: async (since?: string): Promise<any[]> => {
    const all: any[] = [];
    const pageSize = 500;
    for (let page = 0; page < MAX_LIST_PAGES; page++) {
      const params = new URLSearchParams({ limit: String(pageSize), offset: String(page * pageSize) });
      if (since) params.set("since", since);
      const result = await request("GET", `/api/entries?${params.toString()}`);
      all.push(...result);
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
    return request("DELETE", `/api/entries/${encodeURIComponent(clientEntryId)}`);
  },

  openProcessingSession: (dataKeyB64: string) =>
    request("POST", "/api/processing/sessions", { data_key: dataKeyB64 }, {}, { sensitive: true }),
  recompute: (processingToken: string) =>
    request("POST", "/api/insights/recompute", undefined, { "X-Processing-Token": processingToken }),
  insights: () => request("GET", "/api/insights"),
  questionToday: () => request("GET", "/api/questions/today"),

  exportAccount: () => request("GET", "/api/account/export"),
  /** Requires the password-derived verifier: a stolen token cannot erase data. */
  deleteAccount: (verifierB64: string) =>
    request("DELETE", "/api/account", { verifier: verifierB64 }, {}, { sensitive: true }),
  /** Explicit, re-authenticated opt-in for third-party LLM analysis. */
  getLlmConsent: () => request("GET", "/api/account/llm-consent"),
  setLlmConsent: (enabled: boolean, verifierB64: string) =>
    request("PUT", "/api/account/llm-consent", { enabled, verifier: verifierB64 }, {}, { sensitive: true }),
};
