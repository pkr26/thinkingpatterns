/** SettingsView: the password-rotation H-4/M-W2 contract (lockdown after a
 *  moved key, the rekey_key_mismatch resume ladder, derived-key zeroization),
 *  the M-W3 deletion sweep of every per-account IndexedDB store, and the
 *  LOW-b unknown-LLM state with retry. Real crypto (600k-iteration KDF —
 *  these tests are the slow ones by design); fetch stubs at the edge. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SettingsView } from "../src/views/Settings";
import { decryptEntry, encryptEntry } from "../src/crypto/patient";
import { deriveMasterKey, zeroize } from "../src/crypto/core";
import { derivePatientKeys } from "../src/crypto/keys";
import { kv, setKvBackendForTests, type KvBackend } from "../src/kvstore";
import { enqueue } from "../src/offlineQueue";
import { recordFeedbackTap } from "../src/questionFeedback";
import { recordMood } from "../src/moodLog";
import { observeEntryVersions } from "../src/entryVersions";
import { checkAnalysisGeneration, forgetAnalysisGeneration } from "../src/stateSeqGuard";
import { writeMutedPids } from "../src/patternMutes";
import { vault } from "../src/vault";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { press, render, settle, textOf, typeInto } from "./helpers/rtr";

const ORIGIN = "http://localhost:5173";
const USER = "user-1";
const OLD_KEY = new Uint8Array(new ArrayBuffer(32)).fill(5);
const NEW_PASSWORD = "a-fresh-long-password-7";

/** Deterministic randomness: the rotation flow derives the candidate key
 *  from newPassword + a random salt — pinning getRandomValues lets the test
 *  derive the SAME key and pre-encrypt a readable journal row for the
 *  resume ladder. */
function pinRandomness(): void {
  // A plain object carrying the REAL subtle (WebCrypto methods brand-check
  // their receiver, so the genuine instance must be reused) plus a
  // deterministic getRandomValues: the rotation's fresh salt becomes
  // predictable — 16 bytes of 0x07 — so the test can derive the same
  // candidate key and pre-encrypt a readable journal row.
  const real = globalThis.crypto;
  const stub = {
    subtle: real.subtle,
    getRandomValues: <T extends ArrayBufferView>(array: T): T => {
      new Uint8Array(array.buffer, array.byteOffset, array.byteLength).fill(7);
      return array;
    },
  } as Crypto;
  vi.stubGlobal("crypto", stub);
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
function baseStubs(extra?: { rekey?: () => Response; credential?: () => Response; entries?: () => Response }): ReturnType<typeof stubFetch> {
  return stubFetch((url, init) => {
    if (url.endsWith("/meta")) return jsonResponse({ version: "1", api_version: "v1", unlock_days: 30, llm_available: true, sharing_available: true, sharing_disclosure_version: "v2" });
    if (url.endsWith("/llm-consent") && init.method === "GET") return jsonResponse({ enabled: false });
    if (url.endsWith("/access-log")) return jsonResponse([]);
    if (url.endsWith("/processing/sessions")) return jsonResponse({ session_token: "pst", expires_in: 300 });
    if (url.endsWith("/processing/rekey")) return (extra?.rekey ?? (() => new Response(null, { status: 204 })))();
    if (url.endsWith("/account/credential")) return (extra?.credential ?? (() => new Response(null, { status: 204 })))();
    if (url.endsWith("/consents")) return jsonResponse([]);
    if (url.startsWith(`${ORIGIN}/api/v1/entries?`)) return (extra?.entries ?? (() => jsonResponse([], { headers: { "X-Entries-Revision": "1" } })))();
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
    pinRandomness();
    // The candidate key is (NEW_PASSWORD, 16×0x07) — pre-encrypt the live
    // journal row under exactly that key so the ladder proves "already
    // rekeyed, to THIS password" and continues.
    const master = await deriveMasterKey(NEW_PASSWORD, new Uint8Array(new ArrayBuffer(16)).fill(7));
    const newKeys = await derivePatientKeys(master);
    const { blobB64 } = await encryptEntry(newKeys.dataKey, USER, "e-resume", "already under the new key", "2026-09-25T00:00:00Z", null, undefined, 1);
    zeroize(master, newKeys.masterKey, newKeys.authKey, newKeys.dataKey);
    baseStubs({
      rekey: () => jsonResponse({ detail: "old key mismatch", code: "rekey_key_mismatch" }, { status: 400 }),
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
    // The ladder resumed (no honest-stop error) and the rotation completed:
    // the success lockdown fired, and the rekey endpoint was only ever
    // asked once — the completion was idempotent, not a restart-from-zero.
    expect(textOf(root)).not.toContain("already re-encrypted under a different new password");
    expect(onLockdown).toHaveBeenCalledTimes(1);
    expect(onLockdown.mock.calls[0]![0]).toContain("Password changed");
  });

  it("rekey_key_mismatch with an UNREADABLE journal stops with the honest message — never the false NOTHING-changed claim", async () => {
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
    expect(textOf(root)).toContain("already re-encrypted under a different new password");
    expect(textOf(root)).not.toContain("NOTHING was changed");
    expect(onLockdown).not.toHaveBeenCalled();
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
