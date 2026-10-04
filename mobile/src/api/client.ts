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
import type { KdfParams } from "../crypto/keyEnvelope";
import { changeLocalOrigin, changeLocalSessionOwner, advanceLocalWriteScope, localWriteScopeEpoch, assertLocalWritePermit, waitLocalWriteCommits, type LocalWritePermit } from "../localWriteGuard";

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
 *  be replayed as another's (cross-origin KDF poisoning).
 *
 *  Audit 2026-09-28 (LOW): the username part is base64url-encoded — the
 *  same scopeId discipline offlineQueue.ts applies — so the AsyncStorage
 *  key space no longer embeds a readable account name (keys are observable
 *  metadata on a device, e.g. in backups). Encoded, not encrypted: the
 *  VALUE is unchanged. Reads migrate any legacy raw-username key across
 *  (see readThroughMigrate). */
const scopeUser = (username: string): string => Buffer.from(username, "utf8").toString("base64url");
const saltKey = (username: string): string => `@mindpattern/salt_${scopeUser(username)}`;
const legacySaltKey = (username: string): string => `@mindpattern/salt_${username}`;

/** Per-username key-envelope cache key (the same origin-bound discipline
 *  and the same encoded-name form; see api.cacheKeyEnvelope). */
const envelopeKey = (username: string): string => `@mindpattern/keyenvelope_${scopeUser(username)}`;
const legacyEnvelopeKey = (username: string): string => `@mindpattern/keyenvelope_${username}`;

/** Read-through key migration (audit 2026-09-28): when the encoded key is
 *  absent but the legacy raw-username key holds a value, move it across and
 *  retire the old key. Best-effort by constraint — if the rewrite fails the
 *  legacy value is still SERVED (a read must never fail because a cleanup
 *  could not complete); the next read retries the migration. */
async function readThroughMigrate(legacy: string, next: string): Promise<string | null> {
  const epoch = localWriteScopeEpoch();
  let value: string | null = null;
  try {
    value = await AsyncStorage.getItem(next);
  } catch {
    value = null;
  }
  if (value !== null) return value;
  try {
    const old = await AsyncStorage.getItem(legacy);
    if (old === null) return null;
    return await serializedCredentials(async () => {
      assertCredentialEpoch(epoch);
      const current = await AsyncStorage.getItem(next); assertCredentialEpoch(epoch);
      if (current !== null) return current;
      await AsyncStorage.setItem(next, old); assertCredentialEpoch(epoch);
      await AsyncStorage.removeItem(legacy); assertCredentialEpoch(epoch);
      return old;
    });
  } catch {
    try {
      return await AsyncStorage.getItem(legacy);
    } catch {
      return null;
    }
  }
}

/** The cached envelope record: what a v2 (or v1-marker) offline unlock
 *  needs. v2 records carry the wrapped data key + the kdf_params blob the
 *  wrap authenticated under; v1 records are a scheme marker only (offline
 *  v1 unlock keeps using the sealed unlock proof). */
export interface KeyEnvelopeCacheRecord {
  scheme: "v1" | "v2";
  saltB64: string;
  kdfParams: unknown | null;
  wrappedB64: string | null;
}

/** The React Native build-mode global (dev bundle vs release bundle). It is
 *  injected by the Metro environment, not imported — declared here because
 *  this repo ships no RN globals .d.ts. The typeof guard keeps a plain
 *  node evaluation (vitest, scripts) on the release branch instead of
 *  throwing on an undeclared identifier. */
declare const __DEV__: boolean;

/** RELEASE CONFIG POINT (2026-09-26 audit LOW) — the default server origin
 *  for PRODUCTION builds. ***PLACEHOLDER — NOT A REAL DEPLOYMENT***:
 *  operations MUST replace api.mindpattern.example with the real HTTPS
 *  origin at release-config time. A release build left on the placeholder
 *  fails loudly (no such host) — the correct failure; the alternative this
 *  constant exists to end was a release build silently defaulting to a
 *  device-local dev server. */
declare const __API_ORIGIN__: string | null;
export const PRODUCTION_BASE_URL = typeof __API_ORIGIN__ === "string" ? __API_ORIGIN__ : "https://api.mindpattern.example";

/** 2026-09-26 audit LOW: the default is selected by BUILD, not shipped
 *  once: dev builds keep the device-local loopback server, release builds
 *  get the production HTTPS constant above. A user-selected URL (Settings)
 *  always wins over either default; LoginScreen's server disclosure reads
 *  the resolved URL, so it stays honest on both branches. */
export const DEFAULT_BASE_URL =
  typeof __DEV__ !== "undefined" && __DEV__ ? "http://localhost:8000" : PRODUCTION_BASE_URL;

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
/** The measures twin (backend MEASURE_PAGE_BLOB_BYTES): the same 2 MiB
 *  encrypted-blob page budget, opt-in via page_bytes. Audit 2026-09-28
 *  (LOW): the client used to omit it and count rows only — a byte-heavy
 *  page over the server's budget answered 413 instead of continuing. */
export const MEASURE_PAGE_BYTES = 2 * 1024 * 1024;
/** Entry ids this client generates are [A-Za-z0-9_-]; anything else in this
 *  position is at-rest tampering and must never reach the URL path. The
 *  1-64 length band matches the backend exactly (backend/app/schemas.py
 *  CLIENT_ID_PATTERN) — a longer id would be built, queued and retried
 *  forever only to be 422'd at upload. */
const ENTRY_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

/** Consent ids are the server's 32-hex new_id(); the same URL-path hygiene
 *  as entry ids (backend/app/models.py new_id). */
const CONSENT_ID_PATTERN = /^[0-9a-f]{32}$/;

/** L-7 (2026-09-20): server-provided account ids are the backend's 32-hex
 *  new_id(). A login response carrying any other shape is a hostile or
 *  broken server relabeling the account — adopting it verbatim would bind
 *  every future blob's AAD to an id the real server does not know, making
 *  the journal silently undecryptable there. Refuse before persisting. */
const USER_ID_PATTERN = /^[0-9a-f]{32}$/;

/** First-seen origin pin (M-3, 2026-09-20): the login credential is the
 *  derived auth key — there is no reset path — so a user socially
 *  engineered into typing their password at an attacker origin hands over
 *  the account forever. The pin is the device's memory of the FIRST origin
 *  a successful login happened against; LoginScreen renders a prominent
 *  warning whenever the selected origin differs from it, so a phished
 *  "support server" URL is visible BEFORE the password is typed. */
const PINNED_ORIGIN_KEY = "@mindpattern/pinned_origin";

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
  /** The therapist's public wrap key (rotation flow, 2026-09-20): a client
   *  that just rekeyed its data key re-wraps it to the same therapist. */
  therapist_wrap_pub_key?: string;
  /** Voice-sharing grant (VOICE_PLAN 2026-09-29): default false; additive
   *  for older backends — absence reads as OFF, never guessed as on. */
  share_voice?: boolean;
}

/** The pairing-lookup answer: who the code belongs to, before any data
 *  moves. The user sees exactly this before deciding to share.
 *  sas/wrap_key_fingerprint (2026-09-26): the server-computed out-of-band
 *  verification pair — the SAS ("123 456") is an HMAC over the code, the
 *  wrap key DER and the patient id, so a substituted key changes it and
 *  the mismatch is HUMAN-visible. Absent/empty on servers that predate
 *  the field; the screen renders the pair only when well-formed. */
export interface PairingLookup {
  therapist_id: string;
  display_name: string;
  wrap_pub_key: string;
  sas?: string;
  wrap_key_fingerprint?: string;
}

/** GET /auth/key-envelope (bearer): the account's key-scheme state. v2
 *  accounts carry the wrapped random data key (opaque to the server);
 *  v1 accounts answer key_scheme="v1" with null envelope fields. The
 *  server is untrusted — keyScheme.ts sanitizes before anything acts on
 *  it. Unknown fields pass through untouched. */
export interface KeyEnvelopeResponse {
  key_scheme: string;
  salt: string;
  kdf_params: Record<string, unknown> | null;
  wrapped_data_key: string | null;
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

/** Every per-account and per-origin local value: salts, key envelopes,
 *  unlock proofs, recompute stamps, mood logs, pending question feedback,
 *  queue quarantine, analysis-generation marks, entry-version marks. All
 *  of it belongs to the origin it was created against. */
function isOriginBoundKey(key: string): boolean {
  return (
    key.startsWith("@mindpattern/salt_") ||
    // v2 key-envelope cache (2026-09-26): same origin-binding rule as the
    // salt — one server's wrapped data key must never be unwrapped against
    // another server's account (the AAD's username would match, the KEK's
    // salt would not — but fail-closed by deletion is the cleaner wall).
    key.startsWith("@mindpattern/keyenvelope_") ||
    key.startsWith("@mindpattern/unlockproof_") ||
    key.startsWith("@mindpattern/last_recompute_") ||
    // Same prefix as questionFeedback.ts's key() — that module exports no
    // constant to import, so the literal is duplicated here on purpose.
    key.startsWith("@mindpattern/question_feedback.") ||
    key.startsWith("mindpattern.moodlog.") ||
    key.startsWith("@mindpattern/crisis_dialog_") ||
    // Audit 2026-09-28 (LOW): the pending-measure draft (pendingMeasure.ts)
    // and the safety plan (safetyPlan.ts) are per-account local state in the
    // same class as the mood log — a draft keyed under origin A's account
    // must not survive into origin B's fresh session. Same literal-prefix
    // idiom as the mood log above (neither module exports its constant).
    key.startsWith("@mindpattern/pending_measure_") ||
    key.startsWith("@mindpattern/safety_plan_") ||
    // M-1/M-2 (2026-09-20): both rollback guards fail closed once a mark
    // exists — a mark remembered against origin A must never judge origin
    // B's (perfectly honest, lower) generations.
    key.startsWith("mindpattern.stateSeq.") ||
    key.startsWith("mindpattern.entryVersions.")
  );
}

// Credential slots and server selection share one physical transition queue.
// New admission invalidates older work immediately; checks between native
// commits prevent an old transition continuing after a newer one is queued.
let credentialTransitions: Promise<unknown> = Promise.resolve();
function serializedCredentials<T>(run: () => Promise<T>): Promise<T> {
  const pending = credentialTransitions.then(run, run);
  credentialTransitions = pending.catch(() => {}); return pending;
}
function assertCredentialEpoch(epoch: number): void {
  if (epoch !== localWriteScopeEpoch()) throw new ApiError(0, "A newer account/server transition superseded this operation", "stale_operation");
}
async function currentCredentialCache<T>(operation: (check: () => void) => Promise<T>): Promise<T> {
  const epoch = localWriteScopeEpoch();
  return serializedCredentials(async () => {
    const check = () => assertCredentialEpoch(epoch); check();
    const result = await operation(check); check(); return result;
  });
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
  let epoch = advanceLocalWriteScope();
  await serializedCredentials(async () => {
    assertCredentialEpoch(epoch);
    const previous = (await AsyncStorage.getItem(BASE_URL_KEY)) ?? DEFAULT_BASE_URL;
    assertCredentialEpoch(epoch);
    let originChanged = false;
    try {
      originChanged = (await originOf(previous)) !== (await originOf(parsed.url));
    } catch {
      // An old/corrupt setting is never a reason to retain a live credential.
      originChanged = true;
    }
    assertCredentialEpoch(epoch);
    if (originChanged) {
      changeLocalOrigin(); epoch = localWriteScopeEpoch();
      await waitLocalWriteCommits();
      // IMPORTANT ORDERING: erase the old credential BEFORE persisting the new
      // base URL. A request racing this function therefore either (a) reads the
      // old URL and can only send its token to its old origin, or (b) reads the
      // new URL after this wipe and has no token to attach. Persisting first was
      // a real bearer-token exfiltration window.
      assertCredentialEpoch(epoch);
      await secureStore.removeItem(TOKEN_KEY);
      assertCredentialEpoch(epoch);
      await secureStore.removeItem(USER_ID_KEY);
      assertCredentialEpoch(epoch);
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
        assertCredentialEpoch(epoch);
        if (stale.length > 0) await AsyncStorage.multiRemove(stale);
      } catch {
        // getAllKeys unavailable: the session wipe above is the critical part.
      }
    }
    assertCredentialEpoch(epoch);
    await AsyncStorage.setItem(BASE_URL_KEY, parsed.url);
    // Remove a legacy consent value rather than carrying a cleartext exception
    // forward into a later client version.
    assertCredentialEpoch(epoch);
    await AsyncStorage.setItem(INSECURE_OK_KEY, "0");
    assertCredentialEpoch(epoch);
  });
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
  // Account-wide death (2026-09-25 web parity): the 410 funnel keys on
  // these — sanitizeCode erased them before the code-checked gate landed,
  // which is exactly why the status-only check existed.
  "account_deleted",
  "gone",
  "entry_blob_invalid",
  "entry_payload_malformed",
  "feedback_blob_invalid",
  // M-2 (2026-09-20): the replacement's content_version lost a race with
  // another device's edit — retryable after refetching the row.
  "version_conflict",
  // H-1 (2026-09-20): the rotation endpoints' specific failures.
  "rekey_key_mismatch",
  "processing_session_invalid",
  // M-1 (2026-09-28 wire change): PUT /account/password now demands the
  // possession probe (X-Processing-Token) on EVERY call, not just the v1→v2
  // migration — its absence answers 422 with this code (an invalid/expired
  // token still answers 403 processing_session_invalid above). rotation.ts
  // branches on both to fail honestly instead of retrying tokenless.
  "processing_session_required",
  // v2 key scheme (2026-09-26): the OLD credential-rotation endpoint
  // answers this 409 for v2 accounts — swapping the salt without
  // re-wrapping the data-key envelope would strand the random data key
  // behind a locker whose KEK no longer exists. rotation.ts branches on it
  // to surface honest "this account upgraded elsewhere" copy.
  "key_scheme_conflict",
  // The v1→v2 upgrade's possession probe refused the processing session's
  // key: it did not authenticate stored ciphertext (wrong data key). The
  // client must not blindly retry — the envelope would brick the account.
  "envelope_key_mismatch",
  // 2026-09-20 audit H-14: the server returns this 409 when a legacy v1
  // sharing consent cannot cover a measures read; TherapistShareScreen
  // branches on it to show the calm "sharing terms updated" state.
  "disclosure_outdated",
  // Audit 2026-09-28 (code drift): each verified against backend/app —
  // sanitizeCode erased these to undefined before, degrading every branch
  // that keys on them to status-only matching.
  // auth.py: 401 wrong verifier (vs a dead session's plain "unauthorized").
  "invalid_credentials",
  // auth.py/account.py: the account's TOTP second factor states.
  "totp_required",
  "totp_code_invalid",
  // deps.py DEFAULT_ERROR_CODES[400] + middleware/insights explicit uses.
  "bad_request",
  // deps.py DEFAULT_ERROR_CODES[503] + explicit maintenance paths.
  "service_unavailable",
  // account.py: the LLM recompute provider is down (surfaces as retryable).
  "llm_unavailable",
  // Voice journaling (VOICE_PLAN 2026-09-29) — verified against backend/app.
  "voice_consent_required",
  "stt_unconfigured",
  "stt_upstream",
  "stt_unavailable",
  "audio_too_large",
  "audio_storage_unconfigured",
  "audio_storage_failed",
  "audio_quota_exceeded",
  "audio_expired",
  "unknown_entry",
  "consent_voice_share_required",
  // 2026-10-01 audit M17: six backend-emitted codes the allowlist missed.
  // deps.py defaults: therapist-role tokens on journal endpoints, wrong
  // HTTP method, the middleware's body-read deadline, and the last-ditch
  // 500 (the envelope is generic by design, so the client must accept it).
  "forbidden",
  "method_not_allowed",
  "request_timeout",
  "internal_error",
  // account.py: v2 key-scheme endpoints require the versioned body shape.
  "version_required",
  // auth.py/account.py: no recovery kit on this account — reachable from
  // the shipped recovery flow; without the code the Spanish locale fell
  // back to raw English detail.
  "recovery_not_configured",
  // auth.py (2026-10-01 audit C1): the stored recovery kit verifies under
  // the OTHER scheme — retry once with it (protocol negotiation).
  "recovery_scheme_mismatch",
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
  localWritePermit?: LocalWritePermit;
  /** Durable outboxes may flush while the vault is locked. Bind their
   * ciphertext owner to the stored bearer owner at the dispatch boundary. */
  expectedUserId?: string;
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
  const ownershipEpoch = localWriteScopeEpoch();
  let dispatched = false;
  const assertOwnership = (): void => {
    let stale = ownershipEpoch !== localWriteScopeEpoch();
    if (opts.localWritePermit) {
      try { assertLocalWritePermit(opts.localWritePermit); } catch { stale = true; }
    }
    if (stale) throw new ApiError(0, dispatched ? "The account or key generation changed. This request may already have committed; confirm its outcome before retrying." : "The account or key generation changed; no request was sent.", "stale_operation");
  };
  assertOwnership();
  const base = await getBaseUrl();
  assertOwnership();
  // 2026-09-26 audit LOW: parse/validate FIRST. A corrupt persisted base URL
  // (restored backup, tampering) used to reach `new URL(base)` before this
  // graceful guard and escape as a raw TypeError — every caller branches on
  // ApiError, so the refusal must stay the typed surface. The origin below
  // derives from the PARSED url, which round-trips parseServerUrl's
  // origin+path normalization.
  const configured = parseServerUrl(base);
  if (!configured || (configured.insecure && !isLoopbackUrl(configured.url))) {
    throw new ApiError(0, "refusing to send data to an invalid or cleartext remote server URL");
  }
  const actualOrigin = new URL(configured.url).origin;
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
  const token = opts.noBearer ? null : await secureStore.getItem(TOKEN_KEY);
  assertOwnership();
  if (opts.expectedUserId !== undefined) {
    const owner = await secureStore.getItem(USER_ID_KEY);
    assertOwnership();
    if (owner !== opts.expectedUserId) throw new ApiError(0, "The queued ciphertext belongs to another account; no request was sent.", "stale_operation");
    if (!token) throw new ApiError(0, "No authenticated session owns the queued ciphertext; no request was sent.", "stale_operation");
  }
  const headers: Record<string, string> = { "Content-Type": "application/json", ...extraHeaders };
  if (token) headers.Authorization = `Bearer ${token}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  let response: Response;
  // TRANSPORT TRUST POSTURE (2026-09-26 audit MEDIUM, accepted risk):
  // this fetch trusts the PLATFORM TLS stack — system CAs, no SPKI pinning.
  // Deliberate: pinning needs a native networking interceptor (OkHttp
  // CertificatePinner / NSURLSession trust evaluation), i.e. a new native
  // dependency this client does not carry. The compensating mitigations
  // are the first-login origin pin (M-3: a phished "support server" URL is
  // visible before the password is ever typed), redirect:"error" below
  // (a hostile origin cannot bounce credentials off-site), and the
  // cleartext refusal for every non-loopback host. The residual — a MITM
  // with a system-trusted certificate on the REAL origin — is documented
  // in docs/SECURITY_RESIDUALS.md ("Mobile transport residuals") together
  // with the native-pin design for when a native CI build exists.
  try {
    assertOwnership();
    dispatched = true;
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
  assertOwnership();
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
  assertOwnership();
  if (response.status === 204) return opts.includeResponse ? { data: null, response } : null;
  // BODY-READ TIMEOUT (audit 2026-09-28): the headers-phase timer above is
  // cleared the moment fetch() resolves — i.e. when the response HEADERS
  // arrived — which left the body read below unbounded: a server that
  // trickles its body could park the caller forever. Re-arm the SAME
  // controller for the read; an abort during it must surface as the typed
  // timeout, never fall through to the malformed-JSON {} fallback (an
  // empty payload that looks like success).
  const bodyTimer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  let data: any;
  try {
    data = await response.json();
  } catch {
    if (controller.signal.aborted) {
      throw new ApiError(0, `request timed out after ${REQUEST_TIMEOUT_MS / 1000}s`);
    }
    data = {};
  } finally {
    clearTimeout(bodyTimer);
  }
  assertOwnership();
  if (!response.ok) {
    // Audit 2026-09-25: a 410 only means account death when the server says
    // so in its code (account_deleted/gone, exactly the web client's gate).
    // A status-only check would spuriously lock the vault if a future
    // resource-level 410 endpoint appears; 401 stays unconditional.
    const deathCode = sanitizeCode((data as { code?: unknown }).code);
    const isAccountDeath = response.status === 401
      || (response.status === 410 && (deathCode === "account_deleted" || deathCode === "gone"));
    if (isAccountDeath && token !== null) {
      // The bearer token we sent was rejected: the session is dead. A 401
      // is expiry/epoch death; a 410 is account deletion from another
      // device (WEB_PLAN D-8 parity with the web client) — both must lock
      // the vault app-wide BEFORE the caller sees the error, and a hook
      // failure must never mask the ApiError itself.
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
    public code?: ApiErrorCode | "stale_operation",
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

/** The measures twin (audit 2026-09-28): the backend answers 409
 *  collection_changed on a stale X-Measures-Revision, and a client-side pin
 *  mismatch maps to the same retryable shape — one-restart semantics,
 *  exactly the entries contract. */
function measuresRevisionConflict(): ApiError {
  return new ApiError(409, "measures changed while paging; retry the request", "collection_changed");
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
  /** Content generation (audit fix M-2, 2026-09-20): 1 on the server's
   *  first store of the id, +1 per replacement. Absent on pre-2026-09-20
   *  servers — callers treat absence as legacy (version-unverified). */
  content_version?: number;
  /** Unexpired kept-recording metadata (VOICE_PLAN 2026-09-29); absent on
   *  entries without audio and on pre-voice backends. */
  audio?: { attachment_id: string; expires_at: string } | null;
}

/** Strict wire representation for an owner-journal snapshot revision. Keep
 * this as a string: the backend permits the full signed-64-bit range, which
 * JavaScript Numbers cannot represent exactly. */
export type EntriesRevision = string;

/** The measures snapshot marker (X-Measures-Revision): the identical wire
 *  grammar as EntriesRevision — an opaque decimal token, never a Number. */
export type MeasuresRevision = EntriesRevision;

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
  /** 2026-09-30 wave 1: EXCLUSIVE upper date bound (wire `until`) — pairs
   *  with `since` so one month of a multi-year journal is one bounded
   *  walk, not a linear page-through of every newer entry first. */
  until?: string;
  limit?: number;
  offset?: number;
  pageBytes?: number;
  /** A revision returned by a preceding page. The wire name is
   * `expected_revision`; supplying it makes a changed collection return 409
   * instead of silently mixing two snapshots. */
  expectedRevision?: EntriesRevision;
}

/** One measure row as the backend serializes it (MeasureOut). Same
 *  untrusted-server posture as ListedEntry: unknown fields pass through. */
export interface ListedMeasure {
  id: string;
  client_measure_id: string;
  blob: string;
  measure_date: string;
  received_at: string;
}

/** A byte-bounded measures response — the same contract shape as
 *  ListedEntriesPage (audit 2026-09-28). */
export interface ListedMeasuresPage {
  measures: ListedMeasure[];
  nextOffset: number | null;
  revision: MeasuresRevision | null;
}

export interface ListMeasuresPageOptions {
  limit?: number;
  offset?: number;
  pageBytes?: number;
  /** A revision returned by a preceding page (the wire name is
   *  `expected_revision`); a changed collection answers 409 instead of
   *  silently mixing two snapshots. */
  expectedRevision?: MeasuresRevision;
}

function invalidPageResponse(collection: "entry" | "measure"): never {
  throw new ApiError(0, `invalid ${collection} page response — refusing the response`);
}

/** Parse the paging signal as a strict, non-ambiguous integer. The modern
 *  server promises offset + returned-row-count, so accepting a guessed or
 *  malformed offset could skip history or create an unbounded sync loop. An
 *  older server ignores `page_bytes` and has no header; its only safe fallback
 *  is the legacy rule that an exactly-full requested page has another page.
 *  Shared by the entries and measures walks (audit 2026-09-28). */
function pageNextOffset(
  collection: "entry" | "measure",
  header: string | null,
  offset: number,
  rows: readonly unknown[],
  limit: number,
): number | null {
  if (rows.length > limit) invalidPageResponse(collection);
  const expected = offset + rows.length;
  if (!Number.isSafeInteger(expected)) invalidPageResponse(collection);
  if (header === null) return rows.length === limit ? expected : null;
  if (!/^(?:0|[1-9][0-9]*)$/.test(header)) invalidPageResponse(collection);
  const nextOffset = Number(header);
  if (
    !Number.isSafeInteger(nextOffset) ||
    rows.length === 0 ||
    nextOffset !== expected
  ) {
    invalidPageResponse(collection);
  }
  return nextOffset;
}

/** The backend's canonical nonnegative signed-64-bit decimal grammar (the
 * entries AND measures snapshot markers share it). Do not use Number()
 * here: revisions above Number.MAX_SAFE_INTEGER would be rounded and could
 * turn a valid snapshot token into a different request. */
const COLLECTION_REVISION_PATTERN = /^(?:0|[1-9][0-9]{0,18})$/;
const MAX_COLLECTION_REVISION = "9223372036854775807";

function isCollectionRevision(value: unknown): value is EntriesRevision {
  return (
    typeof value === "string" &&
    COLLECTION_REVISION_PATTERN.test(value) &&
    (value.length < MAX_COLLECTION_REVISION.length || value <= MAX_COLLECTION_REVISION)
  );
}

function pageRevision(collection: "entry" | "measure", header: string | null): EntriesRevision | null {
  if (header === null) return null; // headerless servers retain legacy paging
  if (!isCollectionRevision(header)) invalidPageResponse(collection);
  return header;
}

export const api = {
  setSession: async (token: string, userId: string, username?: string, options: { stillCurrent?: () => boolean } = {}) => {
    // L-7 (2026-09-20): a server-controlled account id becomes the vault's
    // owner binding and the AAD owner part of every stored blob — only the
    // backend's exact id shape may be adopted. A mismatched shape is a
    // hostile server relabeling the account; refusing here fails the login
    // visibly instead of corrupting all future ciphertext silently.
    if (!USER_ID_PATTERN.test(userId)) {
      throw new ApiError(0, "the server returned an invalid account id — refusing to trust this server");
    }
    if (options.stillCurrent?.() === false) throw new ApiError(0, "This authentication attempt was retired", "stale_operation");
    changeLocalSessionOwner(userId);
    const epoch = localWriteScopeEpoch();
    const check = () => {
      assertCredentialEpoch(epoch);
      if (options.stillCurrent?.() === false) throw new ApiError(0, "This authentication attempt was retired", "stale_operation");
    };
    return serializedCredentials(async () => {
      try {
        check();
        await waitLocalWriteCommits();
        // All three values are session material and live encrypted at rest
        // (see secureStore): a device backup must not contain a usable token.
        check();
        const previousOwner = await secureStore.getItem(USER_ID_KEY);
        check();
        // Retire the bearer before replacing its identity, and publish the
        // new bearer last. A process/storage interruption at any boundary
        // therefore leaves either the intact old tuple or no usable bearer;
        // it cannot pair old-account ciphertext with a new-account token.
        await secureStore.removeItem(TOKEN_KEY);
        check();
        await secureStore.setItem(USER_ID_KEY, userId);
        check();
        if (username !== undefined) await secureStore.setItem(USERNAME_KEY, username);
        else if (previousOwner !== userId) await secureStore.removeItem(USERNAME_KEY);
        // M-3: pin the origin on first successful authentication. Later logins
        // at a different origin render the warning (see originPinStatus).
        try {
          const pinned = await secureStore.getItem(PINNED_ORIGIN_KEY);
          const origin = canonicalOrigin(await originOf(await getBaseUrl()));
          check();
          if (pinned === null) await secureStore.setItem(PINNED_ORIGIN_KEY, origin);
        } catch {
          // best effort: the warning surface degrades to "unpinned" silently
        }
        check();
        await secureStore.setItem(TOKEN_KEY, token);
        check();
      } catch (err) {
        // Fail closed on our own publication failure. A newer transition
        // owns its own cleanup; never erase credentials it is publishing.
        if (epoch === localWriteScopeEpoch()) {
          changeLocalSessionOwner(null);
          const cleanupEpoch = localWriteScopeEpoch();
          for (const key of [TOKEN_KEY, USER_ID_KEY, USERNAME_KEY]) {
            if (cleanupEpoch !== localWriteScopeEpoch()) break;
            try { await secureStore.removeItem(key); } catch { /* Preserve the original failure; token-last keeps interrupted identity writes unauthenticated. */ }
          }
        }
        throw err;
      }
    });
  },
  /** M-3: the first origin this device ever authenticated against (null
   *  before the first login, or if the pin could not be stored). */
  pinnedOrigin: async (): Promise<string | null> => {
    try {
      return await secureStore.getItem(PINNED_ORIGIN_KEY);
    } catch {
      return null;
    }
  },
  /** M-3: whether the currently selected server differs from the pinned
   *  origin — the LoginScreen warning state. Canonicalized comparison so
   *  loopback alias spellings do not false-alarm. */
  originPinChanged: async (): Promise<boolean> => {
    const pinned = await secureStore.getItem(PINNED_ORIGIN_KEY).catch(() => null);
    if (pinned === null) return false;
    const current = canonicalOrigin(await originOf(await getBaseUrl()));
    return current !== pinned;
  },
  /** M-3: explicitly trust the currently selected origin (called from the
   *  warning's confirm action after the user has verified the URL). */
  confirmCurrentOrigin: async (): Promise<void> => {
    await secureStore.setItem(PINNED_ORIGIN_KEY, canonicalOrigin(await originOf(await getBaseUrl())));
  },
  getUserId: async () => secureStore.getItem(USER_ID_KEY),
  getUsername: async () => secureStore.getItem(USERNAME_KEY),
  clearSession: async () => {
    changeLocalSessionOwner(null);
    const epoch = localWriteScopeEpoch();
    return serializedCredentials(async () => {
      assertCredentialEpoch(epoch);
      await waitLocalWriteCommits();
      assertCredentialEpoch(epoch); await secureStore.removeItem(TOKEN_KEY);
      assertCredentialEpoch(epoch); await secureStore.removeItem(USER_ID_KEY);
      assertCredentialEpoch(epoch); await secureStore.removeItem(USERNAME_KEY);
      assertCredentialEpoch(epoch);
    });
  },
  isLoggedIn: async () => (await secureStore.getItem(TOKEN_KEY)) !== null,

  meta: () => request("GET", `${API_PREFIX}/meta`),

  /** v2 registration (2026-09-26): kdf_params and wrapped_data_key arrive
   *  together or not at all — the pair is enforced HERE (mirroring the
   *  server's 422) so a caller bug can never strand a v1 account whose
   *  client then tries to unwrap, or a v2 registration the server rejects.
   *  The wrapped key is opaque to the server (see crypto/keyEnvelope.ts);
   *  sensitive = the verifier + envelope ship together, redirect-refused. */
  register: (
    username: string,
    saltB64: string,
    authKeyB64: string,
    kdfParams?: KdfParams,
    wrappedDataKeyB64?: string,
  ) => {
    const hasParams = kdfParams !== undefined;
    const hasWrapped = wrappedDataKeyB64 !== undefined;
    if (hasParams !== hasWrapped) {
      throw new ApiError(0, "v2 registration requires kdf_params and wrapped_data_key together");
    }
    return request(
      "POST",
      `${API_PREFIX}/auth/register`,
      {
        username,
        salt: saltB64,
        verifier: authKeyB64,
        ...(hasParams ? { kdf_params: kdfParams } : {}),
        ...(hasWrapped ? { wrapped_data_key: wrappedDataKeyB64 } : {}),
      },
      {},
      { sensitive: true },
    );
  },
  // POST body, never a URL path: usernames must not land in proxy access logs.
  saltFor: (username: string) => request("POST", `${API_PREFIX}/auth/salt`, { username }),
  cacheSalt: async (username: string, saltB64: string) => {
    // Bind the salt to the origin it was served from: an offline unlock
    // under server B must never derive keys with server A's salt.
    // v1 envelope: pre-v1 records were a bare { o, s } — see getCachedSalt.
    return currentCredentialCache(async check => {
      const origin = await getBaseUrl(); check();
      await AsyncStorage.setItem(saltKey(username), JSON.stringify({ v: 1, o: origin, s: saltB64 }));
    });
  },
  /** The last server-known salt for this username FROM THE CURRENT SERVER,
   *  or null. Enables offline vault unlock without cross-origin replay. */
  getCachedSalt: async (username: string) => {
    const epoch = localWriteScopeEpoch();
    const raw = await readThroughMigrate(legacySaltKey(username), saltKey(username));
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
        await serializedCredentials(async () => {
          assertCredentialEpoch(epoch);
          await AsyncStorage.setItem(saltKey(username), JSON.stringify({ v: 1, o: parsed.o, s: parsed.s }));
          assertCredentialEpoch(epoch);
        }).catch(() => {});
      }
      return parsed.s;
    } catch {
      return null; // legacy/corrupt record: refuse rather than guess
    }
  },
  clearCachedSalt: async (username: string) => {
    // Both forms: a clear must be complete whether or not a read ever got
    // to migrate the legacy key across (audit 2026-09-28).
    return currentCredentialCache(async check => {
      await AsyncStorage.removeItem(saltKey(username)); check();
      await AsyncStorage.removeItem(legacySaltKey(username));
    });
  },
  /** v2 key-envelope cache (2026-09-26): the last server-known envelope for
   *  this username FROM THE CURRENT SERVER. The wrapped data key is
   *  password-locked ciphertext (exactly what the server stores — a device
   *  backup yields nothing without the password), so caching it locally is
   *  what makes OFFLINE unlock possible for v2 accounts: unwrap the cached
   *  envelope, and the GCM authentication is the password proof. Origin-
   *  bound like the salt cache; the record carries the scheme so an
   *  offline unlock also knows a v1 account when it sees one. */
  cacheKeyEnvelope: async (username: string, record: KeyEnvelopeCacheRecord) => {
    return currentCredentialCache(async check => {
      const origin = await getBaseUrl(); check();
      await AsyncStorage.setItem(envelopeKey(username), JSON.stringify({ v: 1, o: origin, ...record }));
    });
  },
  getCachedKeyEnvelope: async (username: string): Promise<KeyEnvelopeCacheRecord | null> => {
    const raw = await readThroughMigrate(legacyEnvelopeKey(username), envelopeKey(username));
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw) as { v?: unknown; o?: unknown } & Partial<KeyEnvelopeCacheRecord>;
      if (parsed.v !== 1) return null;
      if (typeof parsed.o !== "string" || parsed.o !== (await getBaseUrl())) return null;
      if (parsed.scheme !== "v1" && parsed.scheme !== "v2") return null;
      if (typeof parsed.saltB64 !== "string") return null;
      if (parsed.scheme === "v2" && (typeof parsed.wrappedB64 !== "string" || parsed.kdfParams === undefined)) {
        return null;
      }
      return {
        scheme: parsed.scheme,
        saltB64: parsed.saltB64,
        kdfParams: parsed.kdfParams ?? null,
        wrappedB64: parsed.wrappedB64 ?? null,
      };
    } catch {
      return null; // legacy/corrupt record: refuse rather than guess
    }
  },
  clearCachedKeyEnvelope: async (username: string) => {
    // Both forms (same completeness constraint as clearCachedSalt).
    return currentCredentialCache(async check => {
      await AsyncStorage.removeItem(envelopeKey(username)); check();
      await AsyncStorage.removeItem(legacyEnvelopeKey(username));
    });
  },
  login: (username: string, authKeyB64: string) =>
    // noBearer: a login 401 means the VERIFIER was wrong (wrong password),
    // never that the stored bearer died — so the vault-lock hook must not
    // fire on it (biometric sessions use this endpoint for the online
    // re-auth check; see reauth.ts).
    // TOKEN OPACITY (2026-09-26): the bearer is an opaque string here — the
    // client never parses it, so the server's newer claims (jti, purpose,
    // ksv) and response fields (key_scheme, role, expires_in) pass through
    // untouched. Consumers read body.token/body.user_id only; keyScheme.ts
    // reads key_scheme separately when it needs the scheme.
    request("POST", `${API_PREFIX}/auth/login`, { username, verifier: authKeyB64 }, {}, { sensitive: true, noBearer: true }),
  /** The account's key-scheme state (bearer). v2 unlock material: salt +
   *  kdf_params + the wrapped random data key; v1 answers null envelope
   *  fields. Nothing here is a client secret — the wrapped key is
   *  password-locked ciphertext — so it ships as a plain GET. */
  keyEnvelope: (): Promise<KeyEnvelopeResponse> => request("GET", `${API_PREFIX}/auth/key-envelope`),
  // --- key-recovery envelope (wave 3, 2026-09-30) -------------------------
  recoveryStatus: (): Promise<{
    enabled: boolean;
    set_at: string | null;
    scheme: "v1" | "v2";
  }> => request("GET", `${API_PREFIX}/account/recovery`),
  setupRecoveryKit: (
    passwordVerifierB64: string,
    recoveryVerifierB64: string,
    wrappedKeyB64: string,
    scheme: "v1" | "v2" = "v2",
  ) =>
    request(
      "PUT",
      `${API_PREFIX}/account/recovery`,
      {
        password_verifier: passwordVerifierB64,
        verifier: recoveryVerifierB64,
        wrapped_key: wrappedKeyB64,
        // 2026-10-01 audit C1: v2 = the verifier is domain-separated HKDF
        // material; the raw recovery key never leaves the device.
        scheme,
      },
      {},
      { sensitive: true },
    ),
  removeRecoveryKit: (passwordVerifierB64: string) =>
    request(
      "DELETE",
      `${API_PREFIX}/account/recovery`,
      undefined,
      { verifier: passwordVerifierB64 },
      { sensitive: true },
    ),
  recoverLogin: (username: string, recoveryVerifierB64: string, scheme: "v1" | "v2" = "v2") =>
    // noBearer: like login, a 401 here means the recovery key was wrong —
    // the vault-lock hook must not fire on it. `scheme` says which
    // derivation the verifier used; a kit stored under the other scheme
    // answers 401 recovery_scheme_mismatch (negotiation, not a miss).
    request(
      "POST",
      `${API_PREFIX}/auth/recover`,
      { username, verifier: recoveryVerifierB64, scheme },
      {},
      { sensitive: true, noBearer: true },
    ),
  resetPasswordWithRecovery: (
    proofB64: string,
    body: { new_salt: string; new_verifier: string; new_kdf_params?: object; wrapped_data_key: string },
    processingToken: string,
  ) =>
    request(
      "PUT",
      `${API_PREFIX}/account/recovery/password`,
      { proof: proofB64, ...body },
      { "X-Processing-Token": processingToken },
      { sensitive: true },
    ),
  /** Per-device sign-out (2026-09-26): the server revokes THIS bearer's
   *  jti; other devices' sessions for the account stay valid. The
   *  account-wide epoch bump now lives only where invalidating everything
   *  is the point (credential rotation, password change, deletion). */
  logout: () => request("POST", `${API_PREFIX}/auth/logout`),

  createEntry: (clientEntryId: string, blobB64: string, entryDate: string, contentVersion?: number, localWritePermit?: LocalWritePermit) =>
    request("POST", `${API_PREFIX}/entries`, {
      client_entry_id: clientEntryId,
      blob: blobB64,
      entry_date: entryDate,
      ...(contentVersion !== undefined ? { content_version: contentVersion } : {}),
    }, {}, { localWritePermit }),
  /** MBC measures (2026-09-19): opaque encrypted questionnaire records. */
  createMeasure: (clientMeasureId: string, blobB64: string, measureDate: string, localWritePermit?: LocalWritePermit) =>
    request(
      "POST",
      `${API_PREFIX}/measures`,
      { client_measure_id: clientMeasureId, blob: blobB64, measure_date: measureDate },
      {}, { localWritePermit },
    ),
  /** One bounded ciphertext page of the patient's own measures, newest
   *  first (the server orders by (measure_date, received_at, id) DESC — a
   *  deterministic total order, so offset pages tile cleanly).
   *  Audit 2026-09-28 (LOW): the entries paging contract, mirrored — sends
   *  page_bytes so a byte-heavy page continues via X-Next-Offset instead of
   *  answering 413, and pins the X-Measures-Revision snapshot the server
   *  serves (backend measures.py) so a concurrent create answers 409
   *  collection_changed rather than silently shifting offset windows. */
  listMeasuresPage: async (options: ListMeasuresPageOptions = {}): Promise<ListedMeasuresPage> => {
    const limit = options.limit ?? 100;
    const offset = options.offset ?? 0;
    const pageBytes = options.pageBytes ?? MEASURE_PAGE_BYTES;
    if (
      !Number.isInteger(limit) ||
      limit < 1 ||
      limit > 500 ||
      !Number.isSafeInteger(offset) ||
      offset < 0 ||
      !Number.isInteger(pageBytes) ||
      pageBytes < 1 ||
      pageBytes > MEASURE_PAGE_BYTES ||
      (options.expectedRevision !== undefined && !isCollectionRevision(options.expectedRevision))
    ) {
      throw new ApiError(0, "invalid measure page request — refusing the request");
    }
    const params = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
      page_bytes: String(pageBytes),
    });
    if (options.expectedRevision !== undefined) params.set("expected_revision", options.expectedRevision);
    const result = (await request(
      "GET",
      `${API_PREFIX}/measures?${params.toString()}`,
      undefined,
      {},
      { includeResponse: true },
    )) as { data: unknown; response: Response };
    if (!Array.isArray(result.data)) invalidPageResponse("measure");
    const measures = result.data as ListedMeasure[];
    const nextOffsetHeader =
      typeof result.response.headers?.get === "function" ? result.response.headers.get("X-Next-Offset") : null;
    const revisionHeader =
      typeof result.response.headers?.get === "function" ? result.response.headers.get("X-Measures-Revision") : null;
    const revision = pageRevision("measure", revisionHeader);
    // Same snapshot-echo rule as entries: a pinned walk that sees a
    // different revision treats it as the retryable conflict, never a mixed
    // history. Headerless legacy servers never send expected_revision.
    if (options.expectedRevision !== undefined && revision !== options.expectedRevision) {
      throw measuresRevisionConflict();
    }
    return { measures, nextOffset: pageNextOffset("measure", nextOffsetHeader, offset, measures, limit), revision };
  },
  /** All stored measures, newest first. M-4/L-55 (2026-09-20): the write
   *  quota is 2000 but a single unpaged GET returned only the server's
   *  default page of 100 — everything older was stored and quota-charged
   *  yet invisible to the patient. Walk byte-bounded pages via
   *  listMeasuresPage (audit 2026-09-28: page_bytes + X-Next-Offset + the
   *  revision pin, exactly the entries walk), dedup by id (a concurrent
   *  insert shifts offset windows by one), and stop at the quota bound so a
   *  lying server cannot keep the app paging forever. One clean restart on
   *  a revision conflict obtains a fresh snapshot; a second is surfaced. */
  listMeasures: async (): Promise<any[]> => {
    for (let attempt = 0; attempt <= MAX_LIST_SNAPSHOT_RESTARTS; attempt += 1) {
      try {
        const rows: any[] = [];
        const seen = new Set<string>();
        const pageSize = 500;
        const MAX_MEASURES = 2000; // mirrors the server's per-user quota
        let offset = 0;
        let revision: MeasuresRevision | null = null;
        let revisionMode: "unknown" | "snapshot" | "legacy" = "unknown";
        const getPage = async (pageOffset: number): Promise<ListedMeasuresPage> => {
          const result = await api.listMeasuresPage({
            limit: pageSize,
            offset: pageOffset,
            pageBytes: MEASURE_PAGE_BYTES,
            ...(revisionMode === "snapshot" && revision !== null ? { expectedRevision: revision } : {}),
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
            // walk — restart rather than mix unpinned and pinned pages.
            throw measuresRevisionConflict();
          }
          return result;
        };
        for (; offset < MAX_MEASURES; ) {
          const result = await getPage(offset);
          for (const row of result.measures) {
            if (row && typeof row.id === "string") {
              if (seen.has(row.id)) continue; // page-boundary drift
              seen.add(row.id);
            }
            rows.push(row);
          }
          if (result.nextOffset === null) break;
          offset = result.nextOffset;
        }
        return rows;
      } catch (err) {
        if (err instanceof ApiError && err.status === 409 && attempt < MAX_LIST_SNAPSHOT_RESTARTS) continue;
        throw err;
      }
    }
    throw new ApiError(0, "could not obtain a stable measures history snapshot");
  },
  /** Offline-queue upload. Identical to createEntry but pinned to the origin
   *  the queue is scoped to: the request refuses to ship (OriginPinnedError,
   *  nothing sent) if the selected server moved, so queued ciphertext can
   *  never ride a different origin's credentials. The queue always sends
   *  content_version 1 (an upload is the first generation of its id). */
  createQueuedEntry: (clientEntryId: string, blobB64: string, entryDate: string, expectedOrigin: string, localWritePermit?: LocalWritePermit) =>
    request(
      "POST",
      `${API_PREFIX}/entries`,
      { client_entry_id: clientEntryId, blob: blobB64, entry_date: entryDate, content_version: 1 },
      {},
      { expectedOrigin, localWritePermit, expectedUserId: localWritePermit?.userId },
    ),
  /** One entry by its stable client id (audit fix M-5, 2026-09-20): the
   *  idempotivity-verification primitive. The offline queue proves a 409
   *  "already exists" answer is REAL before discarding its only local copy
   *  — a hostile/flaky server that 409s without persisting surfaces as a
   *  404 here. Optionally origin-pinned like the queue upload. */
  getEntry: async (clientEntryId: string, expectedOrigin?: string, localWritePermit?: LocalWritePermit) => {
    if (!ENTRY_ID_PATTERN.test(clientEntryId)) {
      throw new ApiError(0, "invalid entry id — refusing the request");
    }
    return request(
      "GET",
      `${API_PREFIX}/entries/${encodeURIComponent(clientEntryId)}`,
      undefined,
      {},
      { expectedOrigin, localWritePermit, expectedUserId: localWritePermit?.userId },
    ) as Promise<ListedEntry>;
  },
  /** Atomically replace an existing encrypted entry. The client id stays
   *  stable, so the encrypted blob remains AAD-bound to the same account and
   *  record. This deliberately avoids delete-then-create data loss.
   *  contentVersion (M-2): the version bound into the replacement blob's
   *  v2 AAD — must be stored+1; a 409 version_conflict means another device
   *  edited first (refetch, re-encrypt, retry). */
  updateEntry: async (clientEntryId: string, blobB64: string, entryDate: string, contentVersion?: number, localWritePermit?: LocalWritePermit) => {
    if (!ENTRY_ID_PATTERN.test(clientEntryId)) {
      throw new ApiError(0, "invalid entry id — refusing the request");
    }
    return request(
      "PUT",
      `${API_PREFIX}/entries/${encodeURIComponent(clientEntryId)}`,
      {
        blob: blobB64,
        entry_date: entryDate,
        ...(contentVersion !== undefined ? { content_version: contentVersion } : {}),
      },
      {}, { localWritePermit },
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
      (options.expectedRevision !== undefined && !isCollectionRevision(options.expectedRevision))
    ) {
      throw new ApiError(0, "invalid entry page request — refusing the request");
    }
    const params = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
      page_bytes: String(pageBytes),
    });
    if (options.since) params.set("since", options.since);
    if (options.until) params.set("until", options.until);
    if (options.expectedRevision !== undefined) params.set("expected_revision", options.expectedRevision);
    const result = (await request(
      "GET",
      `${API_PREFIX}/entries?${params.toString()}`,
      undefined,
      {},
      { includeResponse: true },
    )) as { data: unknown; response: Response };
    if (!Array.isArray(result.data)) invalidPageResponse("entry");
    const entries = result.data as ListedEntry[];
    const nextOffsetHeader =
      typeof result.response.headers?.get === "function" ? result.response.headers.get("X-Next-Offset") : null;
    const revisionHeader =
      typeof result.response.headers?.get === "function" ? result.response.headers.get("X-Entries-Revision") : null;
    const revision = pageRevision("entry", revisionHeader);
    // A modern server must echo the exact snapshot on every successful page.
    // Treat a missing/different header as a retryable conflict rather than
    // allowing a mixed history to reach the decrypting UI. Headerless legacy
    // servers never receive expected_revision in the first place.
    if (options.expectedRevision !== undefined && revision !== options.expectedRevision) {
      throw entriesRevisionConflict();
    }
    return { entries, nextOffset: pageNextOffset("entry", nextOffsetHeader, offset, entries, limit), revision };
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
  /** 2026-09-30 wave 1 (history date-jump): every entry in [since, until)
   *  (dates ISO, until EXCLUSIVE), one bounded walk with the same snapshot
   *  discipline as listEntries. Capped rows per window so a hostile server
   *  cannot pin the phone the way the linear walk's caps prevent. */
  listEntriesWindow: async (since: string, until: string, maxRows = 1500): Promise<ListedEntry[]> => {
    for (let attempt = 0; attempt <= MAX_LIST_SNAPSHOT_RESTARTS; attempt += 1) {
      try {
        const all: ListedEntry[] = [];
        const seen = new Set<string>();
        let offset = 0;
        let revision: EntriesRevision | null = null;
        for (let page = 0; page < MAX_LIST_PAGES; page += 1) {
          const result = await api.listEntriesPage({
            since,
            until,
            limit: 500,
            offset,
            pageBytes: ENTRY_PAGE_BYTES,
            ...(revision !== null ? { expectedRevision: revision } : {}),
          });
          if (revision === null && result.revision !== null) revision = result.revision;
          for (const entry of result.entries) {
            if (seen.has(entry.client_entry_id)) continue;
            if (seen.size >= maxRows) {
              throw new ApiError(0, "entry window exceeded the on-device bound — narrowing the month view");
            }
            seen.add(entry.client_entry_id);
            all.push(entry);
          }
          if (result.nextOffset === null) return all;
          offset = result.nextOffset;
        }
        throw new ApiError(0, "server keeps returning entry continuations — aborting window fetch");
      } catch (err) {
        if (err instanceof ApiError && err.status === 409 && attempt < MAX_LIST_SNAPSHOT_RESTARTS) continue;
        throw err;
      }
    }
    throw new ApiError(0, "could not obtain a stable entry window snapshot");
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

  // 2026-09-26 audit LOW: the account export is a sensitive request like
  // deleteAccount/login/rekey — it ships the bearer and must refuse an
  // unverifiable final URL (strict redirect refusal) instead of trusting it.
  exportAccount: () => request("GET", `${API_PREFIX}/account/export`, undefined, {}, { sensitive: true }),
  /** Requires the password-derived verifier: a stolen token cannot erase
   *  data. The verifier travels in the X-Account-Verifier header (the v1
   *  preference), never the URL; the server still accepts the legacy body
   *  field during the transition. */
  deleteAccount: (verifierB64: string) =>
    request("DELETE", `${API_PREFIX}/account`, undefined, { "X-Account-Verifier": verifierB64 }, { sensitive: true }),
  /** Explicit, re-authenticated opt-in for third-party LLM analysis. */
  getLlmConsent: () => request("GET", `${API_PREFIX}/account/llm-consent`),
  // --- voice journaling (VOICE_PLAN 2026-09-29) ---------------------------
  /** Transcript (spoken language preserved) + detected language + English
   *  translation of the text. Audio exists server-side only for the
   *  upstream call — never stored. */
  transcribeAudio: (audioB64: string, mime: string, durationSeconds: number) =>
    request("POST", `${API_PREFIX}/audio/transcriptions`, {
      audio_b64: audioB64,
      mime,
      duration_seconds: durationSeconds,
    }),
  /** Re-translate an EDITED transcript before saving (payload v3 keeps
   *  english_text in sync with the saved text). */
  translateText: (text: string, sourceLang: string | null) =>
    request("POST", `${API_PREFIX}/audio/translations`, {
      text,
      ...(sourceLang ? { source_lang: sourceLang } : {}),
    }),
  /** Store (or replace) the kept recording for one entry — the blob is the
   *  client-side AES-GCM envelope, opaque to the server. */
  uploadAudioAttachment: (
    clientEntryId: string,
    blobB64: string,
    mime: string,
    durationSeconds: number,
    expectedOrigin?: string,
    localWritePermit?: LocalWritePermit,
  ) =>
    request(
      "POST",
      `${API_PREFIX}/audio/attachments`,
      {
        client_entry_id: clientEntryId,
        blob: blobB64,
        mime,
        duration_seconds: durationSeconds,
      },
      {},
      // 2026-10-01 audit H1: a queued take is pinned to the origin it was
      // recorded under — without the pin, a mid-flush server switch made
      // the remaining rows upload to the NEW origin (404) and the 404
      // handler below DELETED the only copy of the recording.
      { expectedOrigin, localWritePermit, expectedUserId: localWritePermit?.userId },
    ),
  fetchAudioAttachment: (attachmentId: string) =>
    request("GET", `${API_PREFIX}/audio/attachments/${encodeURIComponent(attachmentId)}`),
  deleteAudioAttachment: (attachmentId: string) =>
    request("DELETE", `${API_PREFIX}/audio/attachments/${encodeURIComponent(attachmentId)}`),
  getVoiceConsent: () => request("GET", `${API_PREFIX}/account/voice-consent`),
  setVoiceConsent: (enabled: boolean, verifierB64: string) =>
    request("PUT", `${API_PREFIX}/account/voice-consent`, { enabled, verifier: verifierB64 }, {}, { sensitive: true }),
  setShareVoice: (consentId: string, enabled: boolean, verifierB64: string) =>
    request(
      "PUT",
      `${API_PREFIX}/consents/${encodeURIComponent(consentId)}/share-voice`,
      { enabled },
      { "X-Account-Verifier": verifierB64 },
      { sensitive: true },
    ),
  setLlmConsent: (enabled: boolean, verifierB64: string) =>
    request("PUT", `${API_PREFIX}/account/llm-consent`, { enabled, verifier: verifierB64 }, {}, { sensitive: true }),

  // --- credential & key rotation (audit fix H-1/M-3, 2026-09-20) -----------
  // The recovery path for a captured key or phished verifier: rekey the
  // stored blobs (old data key -> new), re-wrap live therapist grants, then
  // rotate the login credential. See src/rotation.ts for the orchestration
  // and the required ordering (rekey FIRST; the credential rotation kills
  // every bearer at the end).
  /** Server-side re-encryption of every stored blob under a new data key.
   *  Both keys arrive as single-use processing-session tokens; the OLD
   *  password proof gates the operation. All-or-nothing. */
  rekeyStoredData: (oldProcessingToken: string, newProcessingToken: string, verifierB64: string, credential: { operation_id: string; new_salt: string; new_verifier: string; consent_wraps: Array<{ consent_id: string; therapist_wrap_pub_key: string; ephemeral_pub: string; wrapped_key: string }> }) =>
    request(
      "POST",
      `${API_PREFIX}/processing/rekey`,
      credential,
      {
        "X-Processing-Token": oldProcessingToken,
        "X-New-Processing-Token": newProcessingToken,
        "X-Account-Verifier": verifierB64,
      },
      { sensitive: true },
    ),
  /** Retire the current login credential (salt + verifier) for a new one.
   *  Old-password proof required; bumps the server-side epoch, so every
   *  bearer (including this device's) dies with it. v2 accounts are
   *  refused with 409 key_scheme_conflict — changePassword is their path. */
  rotateCredential: (oldVerifierB64: string, newSaltB64: string, newVerifierB64: string) =>
    request(
      "PUT",
      `${API_PREFIX}/account/credential`,
      { verifier: oldVerifierB64, new_salt: newSaltB64, new_verifier: newVerifierB64 },
      {},
      { sensitive: true },
    ),
  /** v2 password change (2026-09-26): swap the credential AND the data-key
   *  envelope in ONE server transaction — the client unwrapped the random
   *  data key locally with the old password and re-wrapped the SAME key
   *  under the new salt (O(1), no corpus rekey). Old-password verifier
   *  proof gates it; the epoch bump still kills every bearer, so the
   *  caller must re-login afterwards. new_kdf_params is optional — omit it
   *  to keep the account's current cost profile (the default blob on v1
   *  accounts upgrading through this endpoint).
   *  M-1 (2026-09-28 wire change): the endpoint also demands POSSESSION of
   *  the current data key on every call — processingToken is a live,
   *  owner-bound session token opened with the UNWRAPPED key (the same
   *  probe the v1→v2 migration path ships), carried in X-Processing-Token.
   *  A missing token answers 422 processing_session_required; an
   *  invalid/expired one 403 processing_session_invalid. */
  changePassword: (
    oldVerifierB64: string,
    newSaltB64: string,
    newVerifierB64: string,
    wrappedDataKeyB64: string,
    processingToken: string,
    newKdfParams?: KdfParams,
  ) =>
    request(
      "PUT",
      `${API_PREFIX}/account/password`,
      {
        verifier: oldVerifierB64,
        new_salt: newSaltB64,
        new_verifier: newVerifierB64,
        wrapped_data_key: wrappedDataKeyB64,
        ...(newKdfParams !== undefined ? { new_kdf_params: newKdfParams } : {}),
      },
      { "X-Processing-Token": processingToken },
      { sensitive: true },
    ),
  /** v1→v2 self-service upgrade (2026-09-26): wrap the account's CURRENT
   *  data key under the password-derived KEK and upload — the account
   *  flips to key_scheme="v2" and future password changes become O(1).
   *  Two independent proofs: the password verifier (header) and POSSESSION
   *  of the current data key (a processing-session token whose key
   *  authenticates stored ciphertext — a wrong key answers 403
   *  envelope_key_mismatch, and storing an envelope over it would brick
   *  every future unlock). */
  upgradeKeyEnvelope: (
    kdfParams: KdfParams,
    wrappedDataKeyB64: string,
    processingToken: string,
    verifierB64: string,
  ) =>
    request(
      "POST",
      `${API_PREFIX}/account/key-envelope/upgrade`,
      { kdf_params: kdfParams, wrapped_data_key: wrappedDataKeyB64 },
      { "X-Processing-Token": processingToken, "X-Account-Verifier": verifierB64 },
      { sensitive: true },
    ),
  /** Swap the wrapped data key of one ACTIVE grant after a rekey. */
  rewrapConsent: (consentId: string, ephemeralPubB64: string, wrappedKeyB64: string, verifierB64: string) => {
    if (!CONSENT_ID_PATTERN.test(consentId)) {
      throw new ApiError(0, "invalid consent id — refusing the request");
    }
    return request(
      "PUT",
      `${API_PREFIX}/consents/${consentId}/rewrap`,
      { ephemeral_pub: ephemeralPubB64, wrapped_key: wrappedKeyB64 },
      { "X-Account-Verifier": verifierB64 },
      { sensitive: true },
    );
  },

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
