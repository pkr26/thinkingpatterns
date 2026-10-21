/** pristine producer-window investigation for App314.
 * Native Response/ReadableStream delivery order, real two Login consumers,
 * actual App/API/crypto/checkpoint. Public api.keyEnvelope forwarding observer
 * returns the same native Promise; no private App closure/state is accessed.
 */


import { act } from "react";
import type { ReactTestRenderer } from "react-test-renderer";
import { afterEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { api, hasSession, sessionUserId } from "../src/api/client";
import { deriveMasterKey, fromBase64, toBase64, zeroize } from "../src/crypto/core";
import { derivePatientKeys } from "../src/crypto/keys";
import { kv, setKvBackendForTests } from "../src/kvstore";
import { stageLocalRotation } from "../src/localRotation";
import { withLock } from "../src/platform";
import { applyLanguagePref, loadFullCatalogs } from "../src/strings";
import { vault } from "../src/vault";
import { jsonResponse, memoryKvBackend, resetTestState, stubFetch } from "./helpers/api";
import { buttonByLabel, flush, isDisabled, render, typeInto } from "./helpers/rtr";

const A = "0123456789abcdef0123456789abcdef";
const B = "fedcba9876543210fedcba9876543210";
const SALT = "AAECAwQFBgcICQoLDA0ODw==";
const PASSWORD = "correct horse battery staple";
function deferred() { let release!: () => void; const promise = new Promise<void>(resolve => { release = resolve; }); return { promise, release }; }
async function completion(label: string, ready: () => boolean): Promise<void> {
  const deadline = Date.now() + 15_000;
  while (!ready()) {
    if (Date.now() >= deadline) throw new Error(`ExecutionError: producer completion timed out: ${label}`);
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 5)); });
  }
  await flush();
}
async function nativeCompletion<T>(label: string, work: Promise<T>): Promise<T> {
  let timer!: ReturnType<typeof setTimeout>;
  try { return await Promise.race([work, new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error(`ExecutionError: producer completion timed out: ${label}`)), 15_000); })]); }
  finally { clearTimeout(timer); }
}
function streamed(data: unknown) {
  let controller!: ReadableStreamDefaultController<Uint8Array>; let cancelled = false, delivered = false;
  const body = new ReadableStream<Uint8Array>({ start(next) { controller = next; }, cancel() { cancelled = true; } });
  const response = new Response(body, { status: 200, headers: { "Content-Type": "application/json" } });
  return { response, deliver() { if (cancelled || delivered) return; delivered = true; controller.enqueue(new TextEncoder().encode(JSON.stringify(data))); controller.close(); }, snapshot() { return { cancelled, delivered }; } };
}
async function submit(root: ReactTestRenderer): Promise<void> {
  expect(isDisabled(root, "Sign in")).toBe(false);
  await act(async () => { root.root.findByType("form").props.onSubmit({ preventDefault() {} }); });
}
afterEach(() => { resetTestState(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it("investigates real protected-envelope return windows across finite native response delivery orders", async () => {
  vi.useRealTimers();
  const witness: { observedWindows: number } = { observedWindows: 0 };
  const check = (action: () => void) => { { action();  } };
  const fixture = await derivePatientKeys(await deriveMasterKey(PASSWORD, fromBase64(SALT)));
  const oldKey = new Uint8Array(new ArrayBuffer(32)).fill(31);
  try {
    await loadFullCatalogs("en");
    for (const order of ["envelope-first", "login-first"] as const) for (const gap of [0, 1, 2, 3, 4, 6, 8, 10]) {
      resetTestState(); applyLanguagePref("en");
      const backend = memoryKvBackend(), onboarding = deferred();
      let onboardingHeld = true;
      setKvBackendForTests({ ...backend, async getItem(key) {
        if (onboardingHeld && key === `mindpattern.onboarding.v1.${A}`) { onboardingHeld = false; await onboarding.promise; }
        return backend.getItem(key);
      } });
      await stageLocalRotation(A, oldKey, fixture.dataKey, { operation_id: "11223344556677889900aabbccddeeff", new_salt: SALT, new_verifier: toBase64(fixture.authKey) });
      const originalCheckpoint = await kv.getItem(`mindpattern.localRotation.${A}`);
      const envelope = streamed({ key_scheme: "v1", salt: SALT, kdf_params: null, wrapped_data_key: null });
      const login = streamed({ token: "synthetic-window-b", user_id: B, expires_in: 86_400, role: "user", key_scheme: "v1" });
      const observations: { outcome: string; owner: string | null; session: string | null; salt?: string; error?: string }[] = [];
      const nativeEnvelope = api.keyEnvelope;
      const observer = vi.spyOn(api, "keyEnvelope").mockImplementation(() => {
        const result = nativeEnvelope();
        void result.then(value => { observations.push({ outcome: "fulfilled", owner: vault.ownerUserId(), session: sessionUserId(), salt: value.salt }); }, error => { observations.push({ outcome: "rejected", owner: vault.ownerUserId(), session: sessionUserId(), error: String(error) }); });
        return result;
      });
      let firstRequests = 0, secondRequests = 0, envelopeRequests = 0;
      stubFetch((url, init) => {
        if (url.endsWith("/auth/salt")) return jsonResponse({ salt: SALT });
        if (url.endsWith("/auth/login")) {
          const data = JSON.parse(String(init.body));
          if (data.verifier !== toBase64(fixture.authKey)) throw new Error("SetupError: actual Login verifier differs from genuine fixture");
          if (data.username === "synthetic_window_a") { firstRequests += 1; return jsonResponse({ token: "synthetic-window-a", user_id: A, expires_in: 86_400, role: "user", key_scheme: "v1" }); }
          secondRequests += 1; return login.response;
        }
        if (url.endsWith("/auth/key-envelope")) {
          if (new Headers(init.headers).get("Authorization") !== "Bearer synthetic-window-a") throw new Error("SetupError: envelope not captured by accountA");
          envelopeRequests += 1; return envelope.response;
        }
        return jsonResponse({ detail: "synthetic unavailable endpoint", code: "not_found" }, { status: 404 });
      });
      let root: ReactTestRenderer | undefined;
      try {
        root = await render(<App />);
        await completion("actual boot", () => buttonByLabel(root!, "Sign in"));
        await typeInto(root, "Username", "synthetic_window_a"); await typeInto(root, "Password", PASSWORD); await submit(root);
        await completion("first actual App awaits protected native stream and public Login is enabled", () => firstRequests === 1 && envelopeRequests === 1 && buttonByLabel(root!, "Sign in") && !isDisabled(root!, "Sign in"));
        await typeInto(root, "Username", "synthetic_window_b"); await submit(root);
        await completion("second actual Login reaches its native response stream", () => secondRequests === 1);
        await act(async () => {
          (order === "envelope-first" ? envelope : login).deliver();
          for (let wave = 0; wave < gap; wave += 1) await Promise.resolve();
          (order === "envelope-first" ? login : envelope).deliver();
        });
        // AppB may already have published onboarding by this observation;
        // the enabled admission was verified before the genuine submission.
        // Requiring the old form to remain would await a retired public UI.
        await completion("second real Login adoptsB and public protected result settles", () => vault.ownerUserId() === B && observations.length === 1);
        const window = observations[0]?.outcome === "fulfilled" && observations[0]?.owner === B && observations[0]?.session === B;
        onboarding.release();
        await act(async () => { await nativeCompletion("genuine App FIFO completion sentinel", withLock("account-transition", async () => undefined)); });
        await flush();
        const checkpointNow = await kv.getItem(`mindpattern.localRotation.${A}`);

        check(() => { expect(firstRequests).toBe(1); expect(secondRequests).toBe(1); expect(envelopeRequests).toBe(1); expect(vault.ownerUserId()).toBe(B); expect(hasSession()).toBe(true); });
        if (window) {
          witness.observedWindows += 1;
          {

{
 expect(checkpointNow).toBe(originalCheckpoint);

}
}
        }
      } finally {
        envelope.deliver(); login.deliver(); onboarding.release();
        if (root) await act(async () => { root!.unmount(); });
        await nativeCompletion("owned producer cleanup", withLock("account-transition", async () => undefined));
        observer.mockRestore();
      }
    }
    if (witness.observedWindows === 0) {
      throw new Error("ExecutionError: producer completion timed out: no protected-result window was observed within sixteen finite native delivery schedules");
    }

  }
  finally {
    zeroize(oldKey, fixture.masterKey, fixture.authKey, fixture.dataKey);


  }
});
