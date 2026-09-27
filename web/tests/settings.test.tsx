/** SettingsView: the password-rotation H-4/M-W2 contract (lockdown after a
 *  moved key, the rekey_key_mismatch resume ladder, derived-key zeroization),
 *  the 2026-09-26 follow-up rotation fixes (B-1 pending-salt resume, B-2
 *  measures probe, B-3 unverifiable-mismatch lockdown, B-4 per-grant rewrap
 *  tolerance), the M-W3 deletion sweep of every per-account IndexedDB store,
 *  and the LOW-b unknown-LLM state with retry. Real crypto (600k-iteration
 *  KDF — these tests are the slow ones by design); fetch stubs at the edge. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SettingsView } from "../src/views/Settings";
import { decryptEntry, encryptEntry } from "../src/crypto/patient";
import { unwrapEnvelope } from "../src/crypto/envelope";
import { buildAad } from "../src/crypto/aad";
import { deriveMasterKey, encrypt, fromBase64, toBase64, zeroize } from "../src/crypto/core";
import { derivePatientKeys } from "../src/crypto/keys";
import { kv, setKvBackendForTests, type KvBackend } from "../src/kvstore";
import { enqueue } from "../src/offlineQueue";
import { buildFeedbackBlob, recordFeedbackTap } from "../src/questionFeedback";
import { recentMoods, recordMood } from "../src/moodLog";
import { observeEntryVersions } from "../src/entryVersions";
import { checkAnalysisGeneration, forgetAnalysisGeneration } from "../src/stateSeqGuard";
import { readMutedPids, writeMutedPids } from "../src/patternMutes";
import { readMeasureCadence } from "../src/measureCadence";
import { savePendingMeasure } from "../src/pendingMeasure";
import { applyLanguagePref, getLanguagePref, getLocale } from "../src/strings";
import { vault } from "../src/vault";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { press, pressAria, render, settle, textOf, textOfNode, typeInto } from "./helpers/rtr";

const ORIGIN = "http://localhost:5173";
const USER = "user-1";
const OLD_KEY = new Uint8Array(new ArrayBuffer(32)).fill(5);
/** M-1 (pentest 2026-09-26): rotation now enforces the full policy, so the
 *  fixture credential must PASS it (3 classes, no common-word family —
 *  the previous "…-password-7" fixture contained a blocked word). */
const NEW_PASSWORD = "a-fresh-long-passphrase-7";
const PENDING_SALT_KEY = "mindpattern.rotatePendingSalt.user-1";

/** B-1 (2026-09-26 follow-up): the resume ladder's production mechanism is
 *  the PENDING SALT the first attempt persists before its rekey — NOT a
 *  pinned RNG. Seed a deterministic salt, derive the candidate key the
 *  same way the flow does, and pre-encrypt readable rows under it. */
const PENDING_SALT = new Uint8Array(new ArrayBuffer(16));
PENDING_SALT.set([11, 22, 33, 44, 55, 66, 77, 88, 99, 111, 12, 13, 14, 15, 16, 17]);

async function derivePendingKeys(): Promise<{ dataKey: Uint8Array<ArrayBuffer> }> {
  const master = await deriveMasterKey(NEW_PASSWORD, PENDING_SALT);
  const keys = await derivePatientKeys(master);
  const dataKey = new Uint8Array(new ArrayBuffer(keys.dataKey.length));
  dataKey.set(keys.dataKey);
  zeroize(master, keys.masterKey, keys.authKey, keys.dataKey);
  return { dataKey };
}

const memoryBackend = (): KvBackend & { dump(): Map<string, string> } => {
  const map = new Map<string, string>();
  return {
    async getItem(k) {
      return map.get(k) ?? null;
    },
    async setItem(k, v) {
      map.set(k, v);
    },
    async removeItem(k) {
      map.delete(k);
    },
    async keys() {
      return [...map.keys()];
    },
    dump: () => map,
  };
};

/** The endpoints every Settings mount touches before any button. */
function baseStubs(extra?: { rekey?: () => Response; credential?: () => Response; entries?: () => Response; measures?: () => Response }): ReturnType<typeof stubFetch> {
  return stubFetch((url, init) => {
    if (url.endsWith("/meta")) return jsonResponse({ version: "1", api_version: "v1", unlock_days: 30, llm_available: true, sharing_available: true, sharing_disclosure_version: "v2" });
    if (url.endsWith("/llm-consent") && init.method === "GET") return jsonResponse({ enabled: false });
    if (url.endsWith("/access-log")) return jsonResponse([]);
    if (url.endsWith("/processing/sessions")) return jsonResponse({ session_token: "pst", expires_in: 300 });
    if (url.endsWith("/processing/rekey")) return (extra?.rekey ?? (() => new Response(null, { status: 204 })))();
    if (url.endsWith("/account/credential")) return (extra?.credential ?? (() => new Response(null, { status: 204 })))();
    if (url.endsWith("/consents")) return jsonResponse([]);
    if (url.startsWith(`${ORIGIN}/api/v1/entries?`)) return (extra?.entries ?? (() => jsonResponse([], { headers: { "X-Entries-Revision": "1" } })))();
    if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) return (extra?.measures ?? (() => jsonResponse([], { headers: { "X-Measures-Revision": "1" } })))();
    return jsonResponse({}, { status: 404 });
  });
}

async function fillRotateForm(root: Awaited<ReturnType<typeof render>>): Promise<void> {
  await typeInto(root, "New password", NEW_PASSWORD);
  await typeInto(root, "Confirm new password", NEW_PASSWORD);
}

beforeEach(() => {
  resetTestState();
  setKvBackendForTests(memoryBackend());
  installSession(USER);
  vault.unlock({ authKey: new Uint8Array(OLD_KEY), dataKey: new Uint8Array(OLD_KEY) }, USER);
});
afterEach(() => {
  vi.unstubAllGlobals();
  setKvBackendForTests(null);
});

describe("SettingsView rotation (H-4/M-W2, audit 2026-09-26)", () => {
  it("M-1 (pentest 2026-09-26): rotation enforces the FULL password policy — policy-barred passwords are rejected before any network step", async () => {
    const fetchSpy = baseStubs();
    const root = await render(<SettingsView onLockdown={vi.fn()} />);
    await settle(40, 3);

    // "password1234": only two character classes — the exact password a
    // length-only gate used to accept on the rotation path.
    await typeInto(root, "New password", "password1234");
    await typeInto(root, "Confirm new password", "password1234");
    await press(root, "Change password");
    await settle(40, 2);
    expect(textOf(root)).toContain("three of");

    // "Password123!": full variety but a blocked common-word family.
    await typeInto(root, "New password", "Password123!");
    await typeInto(root, "Confirm new password", "Password123!");
    await press(root, "Change password");
    await settle(40, 2);
    expect(textOf(root)).toContain("too common or predictable");

    // Rotation must never have started: no processing session was opened.
    const opened = fetchSpy.mock.calls.filter(([u]) =>
      String(u).endsWith("/processing/sessions"),
    );
    expect(opened).toHaveLength(0);
  });

  it("rekey succeeds but the credential rotation fails → LOCKDOWN with the honest moved-key message, and the derived new keys are zeroized", async () => {
    baseStubs({ credential: () => jsonResponse({ detail: "later step exploded" }, { status: 500 }) });
    const core = await import("../src/crypto/core");
    const zeroSpy = vi.spyOn(core, "zeroize");
    const onLockdown = vi.fn();
    const root = await render(<SettingsView onLockdown={onLockdown} />);
    await settle(40, 3);
    await fillRotateForm(root);
    await press(root, "Change password");
    await settle(120, 6);
    // The server HAS moved the corpus to the new key — a live session with
    // the now-dead old key must be locked down, honestly.
    expect(onLockdown).toHaveBeenCalledTimes(1);
    expect(onLockdown.mock.calls[0]![0]).toContain("server has already moved your journal to the new key");
    expect(onLockdown.mock.calls[0]![0]).toContain("repeat the password change");
    // H-4(c): the derived new-key generation is zeroized in finally — the
    // spy keeps the buffer references, so their END state proves the wipe.
    const wiped = zeroSpy.mock.calls
      .flat()
      .filter((b): b is Uint8Array => b instanceof Uint8Array && b.length === 32);
    expect(wiped.length).toBeGreaterThanOrEqual(3);
    for (const buffer of wiped) {
      expect(buffer.every((byte) => byte === 0)).toBe(true);
    }
    zeroSpy.mockRestore();
  });

  it("rekey_key_mismatch with a READABLE journal resumes from the rewrap stage and completes (idempotent finish)", async () => {
    // B-1: the flow must derive from the PERSISTED pending salt (the
    // mechanism a real retry uses), so pre-seed it and pre-encrypt the
    // live journal row under exactly that key.
    window.localStorage.setItem(PENDING_SALT_KEY, toBase64(PENDING_SALT));
    const { dataKey } = await derivePendingKeys();
    const { blobB64 } = await encryptEntry(dataKey, USER, "e-resume", "already under the new key", "2026-09-25T00:00:00Z", null, undefined, 1);
    const rekeyMock = vi.fn(() => jsonResponse({ detail: "old key mismatch", code: "rekey_key_mismatch" }, { status: 400 }));
    baseStubs({
      rekey: rekeyMock,
      entries: () => jsonResponse(
        [{ id: "r1", client_entry_id: "e-resume", blob: blobB64, entry_date: "2026-09-25", received_at: "r", content_version: 1 }],
        { headers: { "X-Entries-Revision": "1" } },
      ),
    });
    const onLockdown = vi.fn();
    const root = await render(<SettingsView onLockdown={onLockdown} />);
    await settle(40, 3);
    await fillRotateForm(root);
    await press(root, "Change password");
    await settle(120, 6);
    // The ladder resumed (no honest-stop lockdown copy) and the rotation
    // completed: the success lockdown fired, the rekey endpoint was only
    // ever asked once (idempotent completion, not a restart-from-zero)...
    expect(textOf(root)).not.toContain("already re-encrypted under a different new password");
    expect(onLockdown).toHaveBeenCalledTimes(1);
    expect(onLockdown.mock.calls[0]![0]).toContain("Password changed");
    expect(rekeyMock).toHaveBeenCalledTimes(1);
    // ...and full completion clears the pending salt.
    expect(window.localStorage.getItem(PENDING_SALT_KEY)).toBeNull();
  });

  it("B-1: a retry after a post-rekey death derives the SAME keys from the persisted pending salt and finishes", async () => {
    // Attempt 1: the rekey lands, the credential step dies → moved-key
    // lockdown. The vault's old key is dead but the CREDENTIAL still
    // works, so the user signs back in and retries.
    const credential = vi.fn()
      .mockImplementationOnce(() => jsonResponse({ detail: "later step exploded" }, { status: 500 }))
      .mockImplementationOnce(() => new Response(null, { status: 204 }));
    baseStubs({ credential });
    const first = vi.fn();
    let root = await render(<SettingsView onLockdown={first} />);
    await settle(40, 3);
    await fillRotateForm(root);
    await press(root, "Change password");
    await settle(120, 6);
    expect(first).toHaveBeenCalledTimes(1);
    expect(first.mock.calls[0]![0]).toContain("repeat the password change");
    // The dying attempt persisted its salt — that is the whole B-1 fix.
    const saltB64 = window.localStorage.getItem(PENDING_SALT_KEY);
    expect(saltB64).toBeTruthy();
    // The corpus now sits under (NEW_PASSWORD, that salt). Derive it here
    // and pre-encrypt the live journal row the retry's ladder will probe.
    const salt = fromBase64(saltB64!);
    const master = await deriveMasterKey(NEW_PASSWORD, salt);
    const keys = await derivePatientKeys(master);
    const { blobB64 } = await encryptEntry(keys.dataKey, USER, "e-retry", "under attempt one's key", "2026-09-25T00:00:00Z", null, undefined, 1);
    zeroize(master, keys.masterKey, keys.authKey, keys.dataKey);
    // Attempt 2 (fresh view, same vault): rekey answers mismatch — with a
    // FRESH salt this would be unverifiable; reusing the pending salt it
    // must resume and complete.
    baseStubs({
      rekey: () => jsonResponse({ detail: "old key mismatch", code: "rekey_key_mismatch" }, { status: 400 }),
      credential: () => new Response(null, { status: 204 }),
      entries: () => jsonResponse(
        [{ id: "r1", client_entry_id: "e-retry", blob: blobB64, entry_date: "2026-09-25", received_at: "r", content_version: 1 }],
        { headers: { "X-Entries-Revision": "1" } },
      ),
    });
    const second = vi.fn();
    root = await render(<SettingsView onLockdown={second} />);
    await settle(40, 3);
    await fillRotateForm(root);
    await press(root, "Change password");
    await settle(120, 6);
    expect(second).toHaveBeenCalledTimes(1);
    expect(second.mock.calls[0]![0]).toContain("Password changed");
    expect(window.localStorage.getItem(PENDING_SALT_KEY)).toBeNull();
  });

  it("B-3: rekey_key_mismatch with an UNREADABLE corpus LOCKS DOWN with the honest message — never a banner over live keys", async () => {
    baseStubs({
      rekey: () => jsonResponse({ detail: "old key mismatch", code: "rekey_key_mismatch" }, { status: 400 }),
      entries: () => jsonResponse(
        [{ id: "r1", client_entry_id: "e-foreign", blob: "QUJD", entry_date: "2026-09-25", received_at: "r", content_version: 1 }],
        { headers: { "X-Entries-Revision": "1" } },
      ),
    });
    const onLockdown = vi.fn();
    const root = await render(<SettingsView onLockdown={onLockdown} />);
    await settle(40, 3);
    await fillRotateForm(root);
    await press(root, "Change password");
    await settle(120, 6);
    // H-4 rule: the corpus is under a key this vault cannot read; the
    // session must not keep writing under the dead old key.
    expect(onLockdown).toHaveBeenCalledTimes(1);
    expect(onLockdown.mock.calls[0]![0]).toContain("already re-encrypted under a different new password");
    expect(textOf(root)).not.toContain("NOTHING was changed");
  });

  it("B-2: an EMPTY journal does not trivially verify while measures sit under the foreign key", async () => {
    // The rekey also moved the PHQ-9 history — the probe must fall through
    // to a measure row and refuse to resume on it.
    window.localStorage.setItem(PENDING_SALT_KEY, toBase64(PENDING_SALT));
    const wrongKey = new Uint8Array(new ArrayBuffer(32)).fill(9);
    const foreignBlob = toBase64(await encrypt(wrongKey, new TextEncoder().encode('{"v":1,"measure":"phq9"}'), buildAad("measure", USER, "m-foreign")));
    baseStubs({
      rekey: () => jsonResponse({ detail: "old key mismatch", code: "rekey_key_mismatch" }, { status: 400 }),
      entries: () => jsonResponse([], { headers: { "X-Entries-Revision": "1" } }),
      measures: () => jsonResponse(
        [{ id: "m1", client_measure_id: "m-foreign", blob: foreignBlob, measure_date: "2026-09-20", received_at: "r" }],
        { headers: { "X-Measures-Revision": "1" } },
      ),
    });
    const onLockdown = vi.fn();
    const root = await render(<SettingsView onLockdown={onLockdown} />);
    await settle(40, 3);
    await fillRotateForm(root);
    await press(root, "Change password");
    await settle(120, 6);
    expect(onLockdown).toHaveBeenCalledTimes(1);
    expect(onLockdown.mock.calls[0]![0]).toContain("already re-encrypted under a different new password");
  });

  it("B-2: an empty journal with measures under the SAME pending-salt key resumes and completes", async () => {
    window.localStorage.setItem(PENDING_SALT_KEY, toBase64(PENDING_SALT));
    const { dataKey } = await derivePendingKeys();
    const readableBlob = toBase64(await encrypt(dataKey, new TextEncoder().encode('{"v":1,"measure":"phq9","score":5}'), buildAad("measure", USER, "m-read")));
    baseStubs({
      rekey: () => jsonResponse({ detail: "old key mismatch", code: "rekey_key_mismatch" }, { status: 400 }),
      entries: () => jsonResponse([], { headers: { "X-Entries-Revision": "1" } }),
      measures: () => jsonResponse(
        [{ id: "m1", client_measure_id: "m-read", blob: readableBlob, measure_date: "2026-09-20", received_at: "r" }],
        { headers: { "X-Measures-Revision": "1" } },
      ),
    });
    const onLockdown = vi.fn();
    const root = await render(<SettingsView onLockdown={onLockdown} />);
    await settle(40, 3);
    await fillRotateForm(root);
    await press(root, "Change password");
    await settle(120, 6);
    expect(onLockdown).toHaveBeenCalledTimes(1);
    expect(onLockdown.mock.calls[0]![0]).toContain("Password changed");
    expect(window.localStorage.getItem(PENDING_SALT_KEY)).toBeNull();
  });

  it("B-7: a successful rotation REWRAPS the mood log, feedback, and mutes under the new key instead of clearing them", async () => {
    // Seed all three per-account stores under the OLD key, plus the
    // pending salt so the test can derive the exact new generation.
    await recordMood(OLD_KEY, USER, "2026-09-24", 0.4);
    await recordFeedbackTap(OLD_KEY, USER, "temporal:work", true);
    await writeMutedPids(OLD_KEY, USER, ["topic:divorce"]);
    window.localStorage.setItem(PENDING_SALT_KEY, toBase64(PENDING_SALT));
    baseStubs();
    const onLockdown = vi.fn();
    const root = await render(<SettingsView onLockdown={onLockdown} />);
    await settle(40, 3);
    await fillRotateForm(root);
    await press(root, "Change password");
    await settle(120, 8);
    expect(onLockdown).toHaveBeenCalledTimes(1);
    // Everything the user built must survive, readable under the NEW key.
    const { dataKey } = await derivePendingKeys();
    const moods = await recentMoods(dataKey, USER);
    expect(moods.map((m) => m.date)).toContain("2026-09-24");
    expect([...(await readMutedPids(dataKey, USER))]).toEqual(["topic:divorce"]);
    const feedbackBlob = await buildFeedbackBlob(dataKey, USER);
    expect(feedbackBlob).toBeTruthy();
  });

  it("B-4: one grant's rewrap failure does not abort the rotation — the flow completes with the partial notice", async () => {
    // A real P-256 SPKI so wrapDataKeyForTherapist succeeds.
    const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
    // Consent ids are 32-hex server ids — the client refuses anything
    // else before issuing the rewrap request.
    const CONSENT_OK = "a".repeat(31) + "1";
    const CONSENT_BAD = "b".repeat(31) + "2";
    const rewrapped: string[] = [];
    stubFetch((url, init) => {
      if (url.endsWith("/meta")) return jsonResponse({ version: "1", api_version: "v1", unlock_days: 30, llm_available: true, sharing_available: true, sharing_disclosure_version: "v2" });
      if (url.endsWith("/llm-consent") && init.method === "GET") return jsonResponse({ enabled: false });
      if (url.endsWith("/access-log")) return jsonResponse([]);
      if (url.endsWith("/processing/sessions")) return jsonResponse({ session_token: "pst", expires_in: 300 });
      if (url.endsWith("/processing/rekey")) return new Response(null, { status: 204 });
      if (url.endsWith("/account/credential")) return new Response(null, { status: 204 });
      if (url.endsWith("/consents") && init.method === "GET") {
        return jsonResponse([
          { id: CONSENT_OK, therapist_id: "t-ok", display_name: "Dr. Available", username: "t-ok", status: "active", therapist_wrap_pub_key: toBase64(spki) },
          { id: CONSENT_BAD, therapist_id: "t-bad", display_name: "Dr. Offline", username: "t-bad", status: "active", therapist_wrap_pub_key: toBase64(spki) },
        ]);
      }
      if (url.includes(`/consents/${CONSENT_OK}`) && url.endsWith("/rewrap")) {
        rewrapped.push(CONSENT_OK);
        return new Response(null, { status: 204 });
      }
      if (url.includes(`/consents/${CONSENT_BAD}`) && url.endsWith("/rewrap")) {
        return jsonResponse({ detail: "therapist server offline" }, { status: 503 });
      }
      return jsonResponse({}, { status: 404 });
    });
    const onLockdown = vi.fn();
    const root = await render(<SettingsView onLockdown={onLockdown} />);
    await settle(40, 3);
    await fillRotateForm(root);
    await press(root, "Change password");
    await settle(120, 6);
    // The surviving grant WAS re-wrapped and the rotation COMPLETED despite
    // the second grant's failure — with the honest partial notice.
    expect(rewrapped).toEqual([CONSENT_OK]);
    expect(onLockdown).toHaveBeenCalledTimes(1);
    expect(onLockdown.mock.calls[0]![0]).toContain("Password changed");
    expect(onLockdown.mock.calls[0]![0]).toContain("could not be re-wrapped");
  });
});

describe("SettingsView key-scheme routing (v2 envelope, 2026-09-26)", () => {
  const V2_NEW_PASSWORD = "a-fresh-long-passphrase-7";
  const KDF_PARAMS = { algorithm: "pbkdf2-sha256", version: 1, iterations: 600000 };
  /** The upgrade flow asks /auth/salt for the CURRENT account salt — the
   *  KEK (and the verifier) derive from (typed password, THIS salt). */
  const UPGRADE_SALT_B64 = toBase64(new Uint8Array(new ArrayBuffer(16)).fill(0));

  /** baseStubs + the GET /auth/key-envelope route every scheme-aware test
   *  needs ("broken" = the honest unknown state; extra.upgrade intercepts
   *  the upgrade POST; extra.password intercepts the v2 change PUT;
   *  extra.consents overrides the grant list). */
  function schemeStubs(
    scheme: "v1" | "v2" | "broken",
    extra: { upgrade?: (url: string, init: RequestInit) => Response; password?: (url: string, init: RequestInit) => Response; consents?: unknown[] } = {},
  ): ReturnType<typeof stubFetch> {
    const mock = baseStubs();
    const inner = mock.getMockImplementation() as (url: string, init: RequestInit) => Response;
    mock.mockImplementation((url: string, init: RequestInit) => {
      if (url.endsWith("/auth/key-envelope")) {
        if (scheme === "broken") return jsonResponse({ detail: "cannot say" }, { status: 500 });
        return scheme === "v2"
          ? jsonResponse({ key_scheme: "v2", salt: UPGRADE_SALT_B64, kdf_params: KDF_PARAMS, wrapped_data_key: "QQ==" })
          : jsonResponse({ key_scheme: "v1", salt: UPGRADE_SALT_B64, kdf_params: null, wrapped_data_key: null });
      }
      if (url.endsWith("/auth/salt")) return jsonResponse({ salt: UPGRADE_SALT_B64 });
      if (extra.upgrade && url.endsWith("/account/key-envelope/upgrade")) return extra.upgrade(url, init);
      if (extra.password && url.endsWith("/account/password")) return extra.password(url, init);
      if (extra.consents && url.endsWith("/consents")) return jsonResponse(extra.consents);
      return inner(url, init);
    });
    return mock;
  }

  it("a v2 account changes its password via the O(1) re-wrap: ONE request, no rekey, no grant re-wrap, honest lockdown", async () => {
    const activeGrant = {
      id: "b".repeat(32),
      therapist_id: "t-1",
      display_name: "Dr. River",
      username: "river",
      status: "active",
      granted_at: "2026-09-01T00:00:00Z",
      revoked_at: null,
      therapist_wrap_pub_key: "K".repeat(124),
    };
    const mock = schemeStubs("v2", { consents: [activeGrant], password: () => new Response(null, { status: 204 }) });
    const onLockdown = vi.fn();
    const vaultKeyB64 = toBase64(vault.get().dataKey);
    const root = await render(<SettingsView onLockdown={onLockdown} />);
    await settle(40, 3);
    // The card routes to the v2 copy: no re-encryption is promised.
    expect(textOf(root)).toContain("without re-encrypting");
    expect(textOf(root)).not.toContain("Upgrade key protection");

    await typeInto(root, "New password", V2_NEW_PASSWORD);
    await typeInto(root, "Confirm new password", V2_NEW_PASSWORD);
    await press(root, "Change password");
    await settle(120, 6);

    const calls = mock.mock.calls as [string, RequestInit][];
    const put = calls.find(([url, init]) => url.endsWith("/account/password") && init.method === "PUT");
    expect(put).toBeTruthy();
    const body = JSON.parse(String(put![1].body)) as Record<string, string>;
    expect(body.verifier).toBe(toBase64(OLD_KEY)); // the vault's auth key
    expect(atob(body.new_salt!).length).toBe(16);
    expect(atob(body.wrapped_data_key!).length).toBe(60);
    // The re-wrapped blob opens the SAME data key under the NEW password —
    // the whole O(1) contract in one assertion.
    const newMaster = await deriveMasterKey(V2_NEW_PASSWORD, fromBase64(body.new_salt!));
    const reopened = await unwrapEnvelope(newMaster, fromBase64(body.new_salt!), "tester", body.wrapped_data_key!, KDF_PARAMS);
    expect(toBase64(reopened)).toBe(vaultKeyB64);
    // And nothing else ran: no rekey, no credential rotation, no consent
    // re-wrap (the data key never rotated), no processing session at all.
    expect(calls.some(([url]) => url.endsWith("/processing/rekey"))).toBe(false);
    expect(calls.some(([url]) => url.endsWith("/account/credential"))).toBe(false);
    expect(calls.some(([url]) => url.endsWith("/processing/sessions"))).toBe(false);
    expect(calls.some(([url, init]) => url.includes("/rewrap") && init.method === "PUT")).toBe(false);
    // Success killed every session (epoch bump) — honest lockdown copy.
    expect(onLockdown).toHaveBeenCalledTimes(1);
    expect(onLockdown.mock.calls[0]![0]).toContain("no re-encryption was needed");
  });

  it("a v1 account sees the upgrade action; the upgrade proves possession + password and flips the card to v2", async () => {
    const upgrade = vi.fn(() => new Response(null, { status: 204 }));
    schemeStubs("v1", { upgrade });
    const root = await render(<SettingsView onLockdown={vi.fn()} />);
    await settle(40, 3);
    expect(textOf(root)).toContain("Upgrade key protection");

    await typeInto(root, "Current password (to authorize the upgrade)", "the-current-passphrase-3");
    await press(root, "Upgrade key protection");
    await settle(120, 6);

    expect(upgrade).toHaveBeenCalledTimes(1);
    const [url, init] = upgrade.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`${ORIGIN}/api/v1/account/key-envelope/upgrade`);
    const headers = init.headers as Record<string, string>;
    // The possession proof: a processing session opened with the vault's
    // CURRENT data key (the stub mints "pst" for every session).
    expect(headers["X-Processing-Token"]).toBe("pst");
    // The password proof derives from the TYPED password (not the vault) —
    // a mistyped password must fail the verifier before any envelope is
    // stored. Prove it: derive the same verifier here.
    const typedMaster = await deriveMasterKey("the-current-passphrase-3", fromBase64(UPGRADE_SALT_B64));
    const typed = await derivePatientKeys(typedMaster);
    expect(headers["X-Account-Verifier"]).toBe(toBase64(typed.authKey));
    const body = JSON.parse(String(init.body)) as Record<string, unknown>;
    expect(body.kdf_params).toEqual(KDF_PARAMS);
    expect(atob(String(body.wrapped_data_key)).length).toBe(60);
    // The wrap IS the vault's current data key under the typed password —
    // the corpus keeps decrypting unchanged.
    const opened = await unwrapEnvelope(typedMaster, fromBase64(UPGRADE_SALT_B64), "tester", String(body.wrapped_data_key), KDF_PARAMS);
    expect(toBase64(opened)).toBe(toBase64(OLD_KEY));
    zeroize(typedMaster, typed.masterKey, typed.authKey, typed.dataKey);
    // Success: honest note, and the password card now routes to v2.
    expect(textOf(root)).toContain("next change will be instant");
    expect(textOf(root)).toContain("without re-encrypting");
    expect(textOf(root)).not.toContain("Upgrade key protection");
  });

  it("a 403 envelope_key_mismatch on upgrade surfaces the honest copy and keeps the account on v1", async () => {
    schemeStubs("v1", {
      upgrade: () => jsonResponse(
        { detail: "the processing session's key did not authenticate stored ciphertext", code: "envelope_key_mismatch" },
        { status: 403 },
      ),
    });
    const root = await render(<SettingsView onLockdown={vi.fn()} />);
    await settle(40, 3);
    await typeInto(root, "Current password (to authorize the upgrade)", "the-current-passphrase-3");
    await press(root, "Upgrade key protection");
    await settle(120, 6);
    expect(textOf(root)).toContain("could not be verified against your stored journal");
    // Still v1: the upgrade action stays available for a fresh retry.
    expect(textOf(root)).toContain("Upgrade key protection");
  });

  it("an UNKNOWN scheme (envelope read failed) blocks the password card honestly instead of guessing", async () => {
    schemeStubs("broken");
    const root = await render(<SettingsView onLockdown={vi.fn()} />);
    await settle(40, 3);
    expect(textOf(root)).toContain("could not be confirmed");
    // No change BUTTON, no upgrade card — guessing could 409 a v2 account
    // or promise v2 behavior to a v1 account. (The card TITLE stays: it is
    // the anchor explaining why the options are hidden.)
    expect(root.root.findAllByType("button").some((node) => textOfNode(node) === "Change password")).toBe(false);
    expect(textOf(root)).not.toContain("Upgrade key protection");
  });
});

describe("SettingsView deletion (M-W3, audit 2026-09-26)", () => {
  it("after deleteAccount, no per-account data remains in any IndexedDB-backed store", async () => {
    // Seed EVERY per-account kv store the app persists.
    await enqueue({ userId: USER, clientEntryId: "e-d-1", blobB64: "QUJD", entryDate: "2026-09-25" });
    await recordFeedbackTap(OLD_KEY, USER, "temporal:work", true);
    await recordMood(OLD_KEY, USER, "2026-09-25", 0.5);
    await observeEntryVersions(USER, OLD_KEY, [{ clientEntryId: "e-d-1", contentVersion: 3 }]);
    await checkAnalysisGeneration(USER, 11, 11);
    await writeMutedPids(OLD_KEY, USER, ["topic:seed"]);
    // Re-audit 2026-09-27: the pending-measure slot rides the sweep too —
    // an in-flight questionnaire must not outlive DELETE /account.
    await savePendingMeasure(OLD_KEY, USER, { kind: "phq9", clientMeasureId: "cm-delete-1", picks: [0, 1, 2, 3, 0, 1, 2, 3, 0], date: "2026-09-26" });
    const seeded = (await kv.keys()).filter((k) => k.startsWith("mindpattern"));
    expect(seeded.length).toBeGreaterThanOrEqual(6);

    baseStubs();
    // The DELETE endpoint itself:
    stubFetch((url, init) => {
      if (url.endsWith("/account") && init.method === "DELETE") return new Response(null, { status: 204 });
      if (url.endsWith("/meta")) return jsonResponse({ version: "1", api_version: "v1", unlock_days: 30, llm_available: true, sharing_available: true, sharing_disclosure_version: "v2" });
      if (url.endsWith("/llm-consent")) return jsonResponse({ enabled: false });
      if (url.endsWith("/access-log")) return jsonResponse([]);
      return jsonResponse({}, { status: 404 });
    });
    const onLockdown = vi.fn();
    const root = await render(<SettingsView onLockdown={onLockdown} />);
    await settle(40, 3);
    await typeInto(root, "Type DELETE to confirm", "DELETE");
    await press(root, "Delete my account");
    await settle(60, 4);
    expect(onLockdown).toHaveBeenCalledTimes(1);
    // Nothing survives for the account: queue (+rejected/quarantine
    // scopes), feedback, mood log, version marks, generation mark, mutes.
    expect((await kv.keys()).filter((k) => k.startsWith("mindpattern"))).toEqual([]);
  });
});

describe("SettingsView LLM unknown state (LOW b, audit 2026-09-26)", () => {
  it("a failed meta/consent read renders the explicit unknown state with a retry — the section never silently disappears", async () => {
    stubFetch((url) => {
      if (url.endsWith("/access-log")) return jsonResponse([]);
      return jsonResponse({ detail: "nope" }, { status: 500 });
    });
    const root = await render(<SettingsView onLockdown={() => undefined} />);
    await settle(40, 3);
    expect(textOf(root)).toContain("Could not confirm whether this server offers LLM analysis");
    // Retry recovers when the server does.
    baseStubs();
    await press(root, "Try again");
    await settle(40, 4);
    expect(textOf(root)).not.toContain("Could not confirm whether this server offers LLM analysis");
    // The section renders the consent switch (redesign 2026-09-26).
    expect(root.root.findAllByType("button").some((node) => node.props.role === "switch")).toBe(true);
  });
});

describe("SettingsView language preference (audit 2026-09-26 LOW)", () => {
  afterEach(() => {
    applyLanguagePref("auto");
  });

  it("the Language control applies the catalog LIVE and persists the choice", async () => {
    baseStubs();
    const root = await render(<SettingsView onLockdown={() => undefined} />);
    await settle(40, 3);
    expect(textOf(root)).toContain("Appearance");
    expect(textOf(root)).toContain("Dark is easier on evening eyes");
    await press(root, "Español");
    await settle(20, 2);
    // The SAME view re-renders in Spanish — no reload needed.
    expect(textOf(root)).toContain("Apariencia");
    expect(textOf(root)).toContain("El modo oscuro descansa la vista");
    expect(getLocale()).toBe("es");
    expect(getLanguagePref()).toBe("es");
    expect(window.localStorage.getItem("mindpattern.language.pref")).toBe("es");
    // Back to Automatic: the device locale wins again, live.
    await press(root, "Automático");
    await settle(20, 2);
    expect(getLanguagePref()).toBe("auto");
    expect(textOf(root)).toContain("Appearance");
  });
});

/** The opt-in check-in cadence (clinical review 2026-09-27): the Settings
 *  toggle + interval persist in the per-account kvstore slot, default OFF
 *  with a 4-week interval, and the safety-plan entry points at the local
 *  encrypted plan view. */
describe("SettingsView check-in cadence + safety plan entry (2026-09-27)", () => {
  it("the toggle persists ON with the 4-week default, and the interval choice persists beside it", async () => {
    baseStubs();
    const root = await render(<SettingsView onLockdown={() => undefined} />);
    await settle(40, 3);
    expect(textOf(root)).toContain("Remind me to complete a check-in");
    // OFF by default (opt-in), nothing in the slot yet.
    expect(await readMeasureCadence(USER)).toEqual({ enabled: false, intervalWeeks: 4, snoozedUntil: null });
    await pressAria(root, "Remind me to complete a check-in");
    await settle(20, 2);
    expect(await readMeasureCadence(USER)).toEqual({ enabled: true, intervalWeeks: 4, snoozedUntil: null });
    // The interval control renders only while the reminder is on.
    expect(textOf(root)).toContain("Every 4 weeks");
    await press(root, "Every 8 weeks");
    await settle(20, 2);
    expect(await readMeasureCadence(USER)).toEqual({ enabled: true, intervalWeeks: 8, snoozedUntil: null });
    // Toggling back off keeps the chosen interval for the next opt-in.
    await pressAria(root, "Remind me to complete a check-in");
    await settle(20, 2);
    expect(await readMeasureCadence(USER)).toEqual({ enabled: false, intervalWeeks: 8, snoozedUntil: null });
  });

  it("the safety-plan entry renders only with the navigation handoff, and opens the plan view", async () => {
    baseStubs();
    const onOpenSafetyPlan = vi.fn();
    const root = await render(<SettingsView onLockdown={() => undefined} onOpenSafetyPlan={onOpenSafetyPlan} />);
    await settle(40, 3);
    expect(textOf(root)).toContain("My safety plan");
    expect(textOf(root)).toContain("never synced, exported, or shared");
    await press(root, "Open my safety plan");
    expect(onOpenSafetyPlan).toHaveBeenCalledTimes(1);
  });
});
