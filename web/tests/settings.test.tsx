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
import { vault } from "../src/vault";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { press, render, settle, textOf, typeInto } from "./helpers/rtr";

const ORIGIN = "http://localhost:5173";
const USER = "user-1";
const OLD_KEY = new Uint8Array(new ArrayBuffer(32)).fill(5);
const NEW_PASSWORD = "a-fresh-long-password-7";
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

describe("SettingsView deletion (M-W3, audit 2026-09-26)", () => {
  it("after deleteAccount, no per-account data remains in any IndexedDB-backed store", async () => {
    // Seed EVERY per-account kv store the app persists.
    await enqueue({ userId: USER, clientEntryId: "e-d-1", blobB64: "QUJD", entryDate: "2026-09-25" });
    await recordFeedbackTap(OLD_KEY, USER, "temporal:work", true);
    await recordMood(OLD_KEY, USER, "2026-09-25", 0.5);
    await observeEntryVersions(USER, OLD_KEY, [{ clientEntryId: "e-d-1", contentVersion: 3 }]);
    await checkAnalysisGeneration(USER, 11, 11);
    await writeMutedPids(OLD_KEY, USER, ["topic:seed"]);
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
    expect(textOf(root)).toContain("Enable LLM analysis");
  });
});
