/** Actual App/Login,
 * rotation journal, encryption and queue upload; no feature-view mocks.
 * The prepared checkpoint models a confirmed remote rotation interrupted
 * before its legitimate local resume, not the entire Settings workflow.
 */


import { act } from "react";
import type { ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { hasSession, sessionUserId } from "../src/api/client";
import { buildAad } from "../src/crypto/aad";
import { decrypt, deriveMasterKey, encrypt, fromBase64, toBase64, zeroize } from "../src/crypto/core";
import { derivePatientKeys } from "../src/crypto/keys";
import { kv, setKvBackendForTests, writeGenerationKey } from "../src/kvstore";
import { stageLocalRotation } from "../src/localRotation";
import * as queue from "../src/offlineQueue";
import { withLock } from "../src/platform";
import { applyLanguagePref, loadFullCatalogs } from "../src/strings";
import * as strings from "../src/strings";
import { vault } from "../src/vault";
import { jsonResponse, memoryKvBackend, resetTestState, stubFetch } from "./helpers/api";
import { buttonByLabel, flush, isDisabled, render, textOf, typeInto } from "./helpers/rtr";

const A = "0123456789abcdef0123456789abcdef";
const B = "fedcba9876543210fedcba9876543210";
const SALT = "AAECAwQFBgcICQoLDA0ODw==";
const PASSWORD = "correct horse battery staple";
const ENTRY = "00112233445566778899aabbccddeeff";

function deferred() { let release!: () => void; const promise = new Promise<void>(resolve => { release = resolve; }); return { promise, release }; }
async function completion(label: string, ready: () => boolean): Promise<void> {
  const deadline = Date.now() + 15_000;
  while (!ready()) {
    if (Date.now() >= deadline) throw new Error(`ExecutionError: producer completion timed out: ${label}`);
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 10)); });
  }
  await flush();
}
async function completedNative<T>(label: string, work: Promise<T>): Promise<T> {
  let timer!: ReturnType<typeof setTimeout>;
  try { return await Promise.race([work, new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error(`ExecutionError: producer completion timed out: ${label}`)), 15_000); })]); }
  finally { clearTimeout(timer); }
}
async function submit(root: ReactTestRenderer): Promise<void> {
  expect(isDisabled(root, "Sign in")).toBe(false);
  await act(async () => { root.root.findByType("form").props.onSubmit({ preventDefault() {} }); });
}
beforeEach(() => { vi.useRealTimers(); resetTestState(); applyLanguagePref("en"); });
afterEach(() => { resetTestState(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it("an invalidated first App adoption cannot upload the successor's old-key queue before its local rotation", async () => {
  const witness: { observations: unknown[] } = { observations: [] };
  const check = (assertion: () => void) => { { assertion();  } };
  const aRead = deferred(), bRead = deferred();
  let aStarted = false, bStarted = false, holdA = false, holdB = false;
  let root: ReactTestRenderer | undefined;
  const oldKey = new Uint8Array(new ArrayBuffer(32)).fill(31);
  const newKeys = await derivePatientKeys(await deriveMasterKey(PASSWORD, fromBase64(SALT)));
  const plain = new TextEncoder().encode(JSON.stringify({ text: "Synthetic successor writing awaiting local key migration" }));
  const aad = buildAad("entry", B, ENTRY, "1");
  try {
    await loadFullCatalogs("en");
    const backend = memoryKvBackend();
    setKvBackendForTests({ ...backend, async getItem(key) {
      if (holdA && key === writeGenerationKey(A)) { holdA = false; aStarted = true; await aRead.promise; }
      if (holdB && key === `mindpattern.localRotation.${B}`) { holdB = false; bStarted = true; await bRead.promise; }
      return backend.getItem(key);
    } });
    const beforeBlob = toBase64(await encrypt(oldKey, plain, aad));
    await queue.enqueue({ userId: B, clientEntryId: ENTRY, blobB64: beforeBlob, entryDate: new Date().toISOString().slice(0, 10) });
    await stageLocalRotation(B, oldKey, newKeys.dataKey, { operation_id: "11223344556677889900aabbccddeeff", new_salt: SALT, new_verifier: toBase64(newKeys.authKey) });
    const queueKey = (await kv.keys()).find(key => /^mindpattern\/queue\.v1\.items\./.test(key));
    expect(queueKey).toBeDefined();
    const beforeQueue = await kv.getItem(queueKey!);
    const beforeJournal = await kv.getItem(`mindpattern.localRotation.${B}`);
    expect(beforeQueue).toContain(beforeBlob); expect(beforeJournal).toBeTruthy();
    const uploads: { user: string; blob: string; id: string }[] = [];
    let logins = 0;
    stubFetch((url, init) => {
      if (url.endsWith("/auth/salt")) return jsonResponse({ salt: SALT });
      if (url.endsWith("/auth/login")) {
        const body = JSON.parse(String(init.body));
        const owner = body.username === "synthetic_first" ? A : B;
        logins += 1;
        return jsonResponse({ token: owner === A ? "synthetic-token-a" : "synthetic-token-b", user_id: owner, expires_in: 86_400, role: "user", key_scheme: "v1" });
      }
      if (url.endsWith("/auth/key-envelope")) return jsonResponse({ key_scheme: "v1", salt: SALT, kdf_params: null, wrapped_data_key: null });
      if (url.endsWith("/entries") && init.method === "POST") {
        const body = JSON.parse(String(init.body));
        uploads.push({ user: new Headers(init.headers).get("Authorization") ?? "", blob: body.blob, id: body.client_entry_id });
        return jsonResponse({ client_entry_id: body.client_entry_id }, { status: 201 });
      }
      return jsonResponse({ detail: "synthetic endpoint unavailable", code: "not_found" }, { status: 404 });
    });
    // Forwarding observer returns the exact production Promise and does
    // not add awaits, delays or producer actions. Assertions inspect real
    // wire requests/ciphertext, never this implementation call count.
    const observedFlushes: Promise<void>[] = [];
    const nativeFlush = queue.flushQueueOnReconnect;
    vi.spyOn(queue, "flushQueueOnReconnect").mockImplementation(() => { const result = nativeFlush(); observedFlushes.push(result); return result; });
    holdA = true; holdB = true;
    root = await render(<App />);
    await completion("actual App boot", () => buttonByLabel(root!, "Sign in"));
    await typeInto(root, "Username", "synthetic_first"); await typeInto(root, "Password", PASSWORD); await submit(root);
    await completion("first real App native generation read admitted and actual form re-enabled", () => aStarted && vault.ownerUserId() === A && buttonByLabel(root!, "Sign in") && !isDisabled(root!, "Sign in"));
    const firstKeys = vault.get();
    await typeInto(root, "Username", "synthetic_successor"); await submit(root);
    await completion("second real Login adopts accountB while first App still owns native account-transition", () => logins === 2 && vault.ownerUserId() === B && buttonByLabel(root!, "Sign in") && !isDisabled(root!, "Sign in"));
    check(() => {
      expect(firstKeys.authKey.every(byte => byte === 0)).toBe(true); expect(firstKeys.dataKey.every(byte => byte === 0)).toBe(true);
      expect(hasSession()).toBe(true); expect(sessionUserId()).toBe(B); expect(vault.get().dataKey).toEqual(newKeys.dataKey);
      expect(bStarted).toBe(false);
    });
    aRead.release();
    await completion("successor App admission reaches its real pending local-rotation read", () => bStarted);
    await completedNative("all already-started real native background flushes", Promise.all(observedFlushes));
    await completedNative("native queue lane completion sentinel", withLock("queue-flush", async () => undefined));

    witness.observations.push({ phase: "successor-migration-held", logins, owner: vault.ownerUserId(), session: sessionUserId(), uploads: [...uploads], queueBefore: beforeQueue, queueNow: await kv.getItem(queueKey!), checkpointBefore: beforeJournal, checkpointNow: await backend.getItem(`mindpattern.localRotation.${B}`) });
    {

{
 expect(uploads).toEqual([]);

}
}
    {

{

      (() => { expect(witness.observations).toHaveLength(1); })();
      expect((witness.observations[0] as any).queueNow).toBe(beforeQueue);
      expect((witness.observations[0] as any).checkpointNow).toBe(beforeJournal);


}
}
    expect(await decrypt(oldKey, fromBase64(beforeBlob), aad)).toEqual(plain);
    bRead.release();
    await completedNative("both genuine queued App producers finish", withLock("account-transition", async () => undefined));
    await completedNative("actual successor's post-recovery background flush completes", Promise.all(observedFlushes));
    await flush();

    const durableCheckpoint = await kv.getItem(`mindpattern.localRotation.${B}`);
    const durableQueue = await kv.getItem(queueKey!);
    witness.observations.push({ phase: "successor-migration-completed", uploads: [...uploads], durableCheckpoint, durableQueue, renderedOnboarding: textOf(root!).includes("Step 1 of 3") });
    {

{

      expect(durableCheckpoint).toBeNull(); expect(textOf(root!)).toContain("Step 1 of 3"); expect(vault.ownerUserId()).toBe(B);


}
}
    {

{

      expect(uploads).toHaveLength(1); expect(uploads[0]?.user).toBe("Bearer synthetic-token-b"); expect(uploads[0]?.id).toBe(ENTRY);
      expect(uploads[0]?.blob).not.toBe(beforeBlob);


}
}
    const currentPlain = await decrypt(newKeys.dataKey, fromBase64(uploads[0]!.blob), aad);
    {

{
 expect(currentPlain).toEqual(plain);

}
}
    zeroize(currentPlain);

  }
  finally {
    aRead.release(); bRead.release();
    if (root) await act(async () => { root!.unmount(); });
    zeroize(oldKey, newKeys.masterKey, newKeys.authKey, newKeys.dataKey, plain);


  }

  // Source33 raw305 is the current() fence AFTER the original catalogue
  // Promise and BEFORE its journal lookup. Retire the current App at that
  // exact native-Promise adoption boundary, not during a later journal read.
  {
    vi.restoreAllMocks(); resetTestState(); applyLanguagePref("en");
    const catalogueAdmitted = deferred(), loginReply = deferred();
    const catalogueObservers: Promise<void>[] = [], background: Promise<void>[] = [];
    let nextRoot: ReactTestRenderer | undefined;
    let submissionActClosed = false, retired = false, armed = true;
    const priorKey = new Uint8Array(new ArrayBuffer(32)).fill(19);
    const currentKeys = await derivePatientKeys(await deriveMasterKey(PASSWORD, fromBase64(SALT)));
    const backend = memoryKvBackend();
    const retiredKVReads: string[] = [];
    setKvBackendForTests({ ...backend, getItem(key) {
      if (retired && key === `mindpattern.localRotation.${A}`) retiredKVReads.push(key);
      return backend.getItem(key);
    } });
    const originalFlush = queue.flushQueueOnReconnect;
    const flushObserver = vi.spyOn(queue, "flushQueueOnReconnect").mockImplementation(() => {
      const original = originalFlush(); background.push(original); return original;
    });
    let restoreCatalogue: (() => void) | undefined;
    try {
      await stageLocalRotation(A, priorKey, currentKeys.dataKey, { operation_id: "aabbccddeeff00112233445566778899", new_salt: SALT, new_verifier: toBase64(currentKeys.authKey) });
      const checkpointBefore = await backend.getItem(`mindpattern.localRotation.${A}`);
      expect(checkpointBefore).toBeTruthy();
      stubFetch(async (url, init) => {
        if (url.endsWith("/auth/salt")) return jsonResponse({ salt: SALT });
        if (url.endsWith("/auth/login")) {
          const body = JSON.parse(String(init.body));
          if (body.username !== "synthetic_catalogue_retirement" || body.verifier !== toBase64(currentKeys.authKey)) throw new Error("SetupError: actual Login fixture differs");
          const response = jsonResponse({ token: "synthetic-catalogue-retirement-a", user_id: A, expires_in: 86_400, role: "user", key_scheme: "v1" });
          await loginReply.promise; return response;
        }
        return jsonResponse({ detail: "synthetic endpoint unavailable", code: "not_found" }, { status: 404 });
      });
      nextRoot = await render(<App />);
      await completion("real current Login before catalogue observer", () => buttonByLabel(nextRoot!, "Sign in"));
      await typeInto(nextRoot, "Username", "synthetic_catalogue_retirement"); await typeInto(nextRoot, "Password", PASSWORD);
      const originalCatalogue = strings.loadFullCatalogs;
      const catalogueObserver = vi.spyOn(strings, "loadFullCatalogs").mockImplementation((locale) => {
        const original = originalCatalogue(locale);
        if (armed) {
          armed = false;
          // Register before App's await receives this SAME original Promise.
          // This observer does not delay, replace, wrap or resolve that Promise.
          const observed = original.then(() => {
            if (!submissionActClosed) throw new Error("SetupError: catalogue settled before the short submit act closed");
            if (!nextRoot) throw new Error("SetupError: current App missing at catalogue settlement");
            const currentRoot = nextRoot;
            act(() => { currentRoot.unmount(); });
            nextRoot = undefined; retired = true;
          });
          observed.catch(() => undefined); catalogueObservers.push(observed); catalogueAdmitted.release();
        }
        return original;
      });
      restoreCatalogue = () => { catalogueObserver.mockRestore(); };
      await submit(nextRoot);
      submissionActClosed = true; loginReply.release();
      // No act scope is held open across native Login/catalogue settlement.
      // A premature observer is a setup refusal, never a guessed timing win.
      await completedNative("original catalogue Promise observer admitted", catalogueAdmitted.promise);
      await completedNative("synchronous current-App unmount observer finished", Promise.all(catalogueObservers));
      await completedNative("original account-transition completes after unmount", withLock("account-transition", async () => undefined));
      expect(retired).toBe(true);
      expect(retiredKVReads, "A retired App must not begin its rotation-journal KV read after the original catalogue Promise settles").toEqual([]);
      expect(await backend.getItem(`mindpattern.localRotation.${A}`)).toBe(checkpointBefore);
    } finally {
      loginReply.release();
      const cleanupFaults: unknown[] = [];
      try { if (nextRoot) await act(async () => { nextRoot!.unmount(); }); } catch (error) { cleanupFaults.push(error); }
      try { await completedNative("owned original catalogue observers retire", Promise.all(catalogueObservers)); } catch (error) { cleanupFaults.push(error); }
      try { await completedNative("owned original App transition retires", withLock("account-transition", async () => undefined)); } catch (error) { cleanupFaults.push(error); }
      try { await completedNative("owned original background flushes retire", Promise.all(background)); } catch (error) { cleanupFaults.push(error); }
      try { restoreCatalogue?.(); flushObserver.mockRestore(); }
      finally { try { resetTestState(); } finally { zeroize(priorKey, currentKeys.masterKey, currentKeys.authKey, currentKeys.dataKey); } }
      if (cleanupFaults.length) throw new Error("SetupError: owned original pre-journal producer cleanup failed", { cause: cleanupFaults[0] });
    }
  }
});
