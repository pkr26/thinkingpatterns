/**
 * LIVE dual-client drill (WEB_PLAN P5.11, matrix L3) — skipped unless
 * LIVE_DRILL=1. Drives TWO full client sessions ("device A" and "device B")
 * against one live backend and the same account, scripting the sync
 * contract's race rows: concurrent creates, the version-CAS edit race,
 * delete-vs-edit, cross-session visibility, and the epoch-death funnel
 * (logout on one device kills the other's token).
 *
 *   MINDPATTERN_ENV=development uvicorn app.main:app --port 8010
 *   LIVE_DRILL=1 LIVE_DRILL_ORIGIN=http://localhost:8010 npx vitest run \
 *     tests/live/dualClient.test.ts
 *
 * Scope note (recorded in WEB_PLAN P5): mobile's client module cannot load
 * under node without its RN mocks, so the L3 harness drives two web-client
 * sessions — the SERVER-mediated contract (idempotency, CAS, revisions,
 * epochs) is client-agnostic, and the mobile client's behavior against the
 * same contract is pinned by mobile/tests/twoWriter.test.ts plus the
 * byte-level interop fixtures.
 */
import { afterEach, describe, expect, it } from "vitest";
import { auth, clearSession, setSession, setSessionExpiredHandler, type TokenResponse } from "../../src/api/client";
import { decryptEntry, encryptEntry } from "../../src/crypto/patient";
import { deriveMasterKey, toBase64 } from "../../src/crypto/core";
import { derivePatientKeys } from "../../src/crypto/keys";
import { newClientEntryId } from "../../src/entryId";
import { localDateISO } from "../../src/dates";
import { randomBytes } from "../../src/platform";
import { listEntriesWalk } from "../../src/api/client";
import { vault } from "../../src/vault";

const live = process.env.LIVE_DRILL === "1";
const BACKEND = process.env.LIVE_DRILL_ORIGIN ?? "http://localhost:8000";

describe.skipIf(!live)("dual-client sync drill (two sessions, one account)", () => {
  afterEach(() => {
    clearSession();
    vault.lock();
    setSessionExpiredHandler(null);
  });

  it("matrix rows: create-create, edit race (CAS), cross-visibility, delete-vs-edit, epoch death", async () => {
    const realWindow = (globalThis as { window?: unknown }).window;
    delete (globalThis as { window?: unknown }).window;
    (globalThis as { window?: unknown }).window = { location: { origin: BACKEND } };

    const username = `web.dual.${Date.now().toString(36)}`;
    const salt = randomBytes(16);
    const keys = await derivePatientKeys(await deriveMasterKey("dual-client-drill-password-1", salt));
    const registered: TokenResponse = await auth.register(username, toBase64(salt), toBase64(keys.authKey));

    // ---- device A session ----
    setSession(registered.token, registered.user_id, username);
    vault.unlock(keys, registered.user_id);

    const date = localDateISO();
    const idA = newClientEntryId(date);
    const a1 = await encryptEntry(keys.dataKey, registered.user_id, idA, "Device A writes first.", new Date().toISOString(), 0, undefined, 1);
    const { api } = await import("../../src/api/client");
    await api.createEntry(idA, a1.blobB64, date, 1);

    // ---- concurrent create: device B (a second login on the same account)
    // writes a DIFFERENT entry the same day — both must coexist (S-2). ----
    const relogin: TokenResponse = await auth.login(username, toBase64(keys.authKey));
    expect(relogin.user_id).toBe(registered.user_id);
    const tokenA = registered.token;
    setSession(relogin.token, registered.user_id, username); // now B's token is live
    const idB = newClientEntryId(date);
    const b1 = await encryptEntry(keys.dataKey, registered.user_id, idB, "Device B writes concurrently.", new Date().toISOString(), 0, undefined, 1);
    await api.createEntry(idB, b1.blobB64, date, 1);

    // Cross-visibility (S-1): A's pull — via a fresh walk under B's session —
    // sees both entries and decrypts both.
    const both = await listEntriesWalk();
    expect(both.map((row) => row.client_entry_id).sort()).toEqual([idA, idB].sort());
    const decodedA = await decryptEntry(keys.dataKey, registered.user_id, idA, both.find((r) => r.client_entry_id === idA)!.blob, 1);
    expect(decodedA.text).toBe("Device A writes first.");

    // ---- edit race (S-3): B edits idA at version 2; then A (stale version
    // echo) tries version 2 again → 409 version_conflict. ----
    const b2 = await encryptEntry(keys.dataKey, registered.user_id, idA, "B edited first.", new Date().toISOString(), 0, undefined, 2);
    await api.updateEntry(idA, b2.blobB64, date, 2);
    const a2stale = await encryptEntry(keys.dataKey, registered.user_id, idA, "A's competing edit.", new Date().toISOString(), 0, undefined, 2);
    const race = await api.updateEntry(idA, a2stale.blobB64, date, 2).catch((err: unknown) => err as { code?: string; status?: number });
    expect((race as { code?: string }).code).toBe("version_conflict");
    // A recovers per contract: refetch, re-apply on top at version 3.
    const current = await api.getEntry(idA);
    expect(current.content_version).toBe(2);
    const a3 = await encryptEntry(keys.dataKey, registered.user_id, idA, "A reapplied on top.", new Date().toISOString(), 0, undefined, 3);
    await api.updateEntry(idA, a3.blobB64, date, 3);

    // ---- delete-vs-edit (S-4): editing a deleted id answers 404. ----
    await api.deleteEntry(idB);
    const b2editDeleted = await encryptEntry(keys.dataKey, registered.user_id, idB, "edit of a deleted row", new Date().toISOString(), 0, undefined, 2);
    const deleted = await api.updateEntry(idB, b2editDeleted.blobB64, date, 2).catch((err: unknown) => err as { status?: number });
    expect((deleted as { status?: number }).status).toBe(404);

    // ---- epoch death (D-8): B logs out — A's token must die on next use. ----
    await api.logout(); // B's logout bumps the account epoch
    setSession(tokenA, registered.user_id, username); // A's stale session
    let death: { status?: number; code?: string } | null = null;
    setSessionExpiredHandler((err) => {
      death = { status: err.status, code: err.code };
    });
    await expect(listEntriesWalk()).rejects.toThrow();
    expect((death as { status?: number } | null)?.status).toBe(401);

    console.log("[dual-client drill] matrix rows green:", username);
    delete (globalThis as { window?: unknown }).window;
    (globalThis as { window?: unknown }).window = realWindow;
  });
});
