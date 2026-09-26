/**
 * LIVE drill (P3 verification gate) — skipped unless LIVE_DRILL=1. Runs the
 * REAL client modules (crypto + api) against the REAL backend:
 *
 *   MINDPATTERN_ENV=development uvicorn app.main:app --port 8000   (backend/)
 *   cd web && LIVE_DRILL=1 npx vitest run tests/live/drill.test.ts
 *
 * The api client's same-origin policy accepts the explicit loopback origin
 * in the test build; the drill repoints the shim's origin at :8000.
 */
import { afterEach, describe, expect, it } from "vitest";
import { api, auth, clearSession, hasSession, setSession } from "../../src/api/client";
import { deriveMasterKey, fromBase64, toBase64 } from "../../src/crypto/core";
import { derivePatientKeys } from "../../src/crypto/keys";
import { randomBytes } from "../../src/platform";
import { vault } from "../../src/vault";

const live = process.env.LIVE_DRILL === "1";
const BACKEND = process.env.LIVE_DRILL_ORIGIN ?? "http://localhost:8000";

describe.skipIf(!live)("live drill against the dev backend", () => {
  afterEach(() => {
    clearSession();
    vault.lock();
  });

  it("register → session → meta → insights(baseline) → re-login → logout", async () => {
    // Repoint the shim origin at the backend (loopback is permitted in the
    // test build). The shim defines `window` non-writable but configurable —
    // delete first, then assign, and restore at the end.
    const realWindow = (globalThis as { window?: unknown }).window;
    delete (globalThis as { window?: unknown }).window;
    (globalThis as { window?: unknown }).window = { location: { origin: BACKEND } };

    const username = `web.drill.${Date.now().toString(36)}`;
    const password = "drill-password-long-enough-1";
    const salt = randomBytes(16);
    const saltB64 = toBase64(salt);
    const keys = await derivePatientKeys(await deriveMasterKey(password, salt));

    const registered = await auth.register(username, saltB64, toBase64(keys.authKey));
    expect(registered.role).toBe("user");
    expect(registered.token).toBeTruthy();

    // Install the session exactly as the real login flow does.
    setSession(registered.token, registered.user_id, username);
    vault.unlock(keys, registered.user_id);
    expect(hasSession()).toBe(true);

    const meta = await api.meta();
    expect(meta.api_version).toBe("v1");
    expect(meta.unlock_days).toBeGreaterThan(0);

    const insights = await api.insights();
    expect(insights.phase).toBe("baseline");
    expect(insights.active_days).toBe(0);
    expect(insights.blob).toBeNull(); // nothing is decrypted before the threshold

    // A fresh derivation must reproduce the same verifier (same salt).
    const again = await derivePatientKeys(await deriveMasterKey(password, fromBase64(saltB64)));
    expect(toBase64(again.authKey)).toBe(toBase64(keys.authKey));
    const relogin = await auth.login(username, toBase64(again.authKey));
    expect(relogin.user_id).toBe(registered.user_id);

    await api.logout();
    // The real App locks down the instant logout returns (the epoch bump
    // killed this token account-wide); mirror that, then prove the client
    // refuses further calls. Keeping the dead token would surface the
    // server's 401 "invalid token" — also correct, but not this flow.
    clearSession();
    vault.lock();
    await expect(api.insights()).rejects.toThrow("not signed in");

    console.log("[live drill] register/login/logout round-trip OK:", username);
    delete (globalThis as { window?: unknown }).window;
    (globalThis as { window?: unknown }).window = realWindow;
  });

  it("P4: entry create → byte-paged walk → decrypt → edit (versioned) → delete", async () => {
    const realWindow = (globalThis as { window?: unknown }).window;
    delete (globalThis as { window?: unknown }).window;
    (globalThis as { window?: unknown }).window = { location: { origin: BACKEND } };

    const username = `web.drill.e.${Date.now().toString(36)}`;
    const salt = randomBytes(16);
    const keys = await derivePatientKeys(await deriveMasterKey("drill-password-long-enough-1", salt));
    const token = await auth.register(username, toBase64(salt), toBase64(keys.authKey));
    setSession(token.token, token.user_id, username);
    vault.unlock(keys, token.user_id);
    const { encryptEntry, decryptEntry } = await import("../../src/crypto/patient");
    const { newClientEntryId } = await import("../../src/entryId");
    const { localDateISO } = await import("../../src/dates");

    const entryId = newClientEntryId(localDateISO());
    const created = await encryptEntry(keys.dataKey, token.user_id, entryId, "A drill entry, calm and quiet.", new Date().toISOString(), 0.3, { sleep: 4, tags: ["rest"] }, 1);
    await api.createEntry(entryId, created.blobB64, localDateISO(), 1);

    const walk = await (await import("../../src/api/client")).listEntriesWalk();
    expect(walk.length).toBe(1);
    const decoded = await decryptEntry(keys.dataKey, token.user_id, walk[0]!.client_entry_id, walk[0]!.blob, walk[0]!.content_version);
    expect(decoded.text).toBe("A drill entry, calm and quiet.");
    expect(decoded.v).toBe(2);
    expect(decoded.sleep).toBe(4);

    // A versioned edit (the multi-device CAS contract):
    const edited = await encryptEntry(keys.dataKey, token.user_id, entryId, "Edited on the web client.", new Date().toISOString(), 0, undefined, 2);
    await api.updateEntry(entryId, edited.blobB64, localDateISO(), 2);
    const afterEdit = await api.getEntry(entryId);
    expect(afterEdit.content_version).toBe(2);

    await api.deleteEntry(entryId);
    const afterDelete = await (await import("../../src/api/client")).listEntriesWalk();
    expect(afterDelete.length).toBe(0);

    console.log("[live drill] entry create/walk/edit/delete round-trip OK");
    clearSession();
    vault.lock();
    delete (globalThis as { window?: unknown }).window;
    (globalThis as { window?: unknown }).window = realWindow;
  });
});

describe.skipIf(process.env.LIVE_DEMO !== "1")("P6: the seeded demo account surfaces real pattern cards", () => {
  it("login → insights → decrypt → patterns with evidence fields", async () => {
    const realWindow = (globalThis as { window?: unknown }).window;
    delete (globalThis as { window?: unknown }).window;
    (globalThis as { window?: unknown }).window = { location: { origin: BACKEND } };

    const saltResponse = await auth.saltFor("demo");
    const keys = await derivePatientKeys(await deriveMasterKey("demo-patterns-2026", fromBase64(saltResponse.salt)));
    const token = await auth.login("demo", toBase64(keys.authKey));
    setSession(token.token, token.user_id, "demo");
    vault.unlock(keys, token.user_id);

    const summary = await api.insights();
    expect(summary.phase).not.toBe("baseline");
    expect(summary.blob).toBeTruthy();
    const { decryptInsights } = await import("../../src/crypto/patient");
    const payload = await decryptInsights(keys.dataKey, token.user_id, summary.blob!);
    expect(payload.v).toBe(2);
    const stats = payload.stats as { patterns?: { kind: string; label: string; occurrences: number; detail: { pattern_pid?: string; pattern_state?: string } }[] };
    expect(Array.isArray(stats.patterns)).toBe(true);
    expect(stats.patterns!.length).toBeGreaterThan(0);
    const withPid = stats.patterns!.find((pattern) => pattern.detail.pattern_pid);
    expect(withPid).toBeDefined();
    console.log(`[demo drill] ${stats.patterns!.length} pattern cards decrypt, e.g.: ${withPid!.label}`);

    clearSession();
    vault.lock();
    delete (globalThis as { window?: unknown }).window;
    (globalThis as { window?: unknown }).window = realWindow;
  });
});
