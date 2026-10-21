/** regression draft. Copy to web/tests in a disposable pristine
 * lane; promote only after the initial sequential campaigns finish.
 *
 * App and LoginView, session/vault, API request core, PBKDF2-600k, HKDF and
 * AES-GCM are real production consumers. Only server responses, persistent
 * storage and FIFO origin lock admission use the existing Node test seams.
 * A contended account-transition lane is supported by App's own adoption
 * and sign-out consumers; this does not claim native browser lock coverage.
 */


import { act } from "react";
import type { ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { hasSession, sessionAbortSignal, sessionUserId } from "../src/api/client";
import { deriveMasterKey, fromBase64, toBase64, zeroize } from "../src/crypto/core";
import { createRegistrationEnvelope, unwrapEnvelope } from "../src/crypto/envelope";
import { withLock } from "../src/platform";
import { applyLanguagePref } from "../src/strings";
import { vault } from "../src/vault";
import { jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { buttonByLabel, flush, isDisabled, render, textOf, textOfNode, typeInto } from "./helpers/rtr";

const SALT = "AAECAwQFBgcICQoLDA0ODw==";
const PASSWORD = "correct horse battery staple";
const FIRST_OWNER = "0123456789abcdef0123456789abcdef";
const NEXT_OWNER = "fedcba9876543210fedcba9876543210";
const FIRST_USERNAME = "queued_patient";
const NEXT_USERNAME = "refused_patient";
const SIGN_IN = "Sign in";

type TraceRow = { phase: string; name?: string; id?: number; at: number };

type Witness = { trace: TraceRow[] };
type Refusal = {
  name: string;
  initialMutantId: string;
  errorText: string;
  token: Record<string, unknown>;
  envelope?: Record<string, unknown>;
};

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

function installFifoLocks(trace: TraceRow[]): void {
  const chains = new Map<string, Promise<unknown>>();
  let nextId = 0;
  const locks = {
    request<T>(name: string, callback: () => Promise<T>): Promise<T> {
      const id = ++nextId;
      trace.push({ phase: "lock-requested", name, id, at: Date.now() });
      const admission = chains.get(name) ?? Promise.resolve();
      const result = admission.then(async () => {
        trace.push({ phase: "lock-admitted", name, id, at: Date.now() });
        try { return await callback(); }
        finally { trace.push({ phase: "lock-completed", name, id, at: Date.now() }); }
      });
      chains.set(name, result.catch(() => undefined));
      return result;
    },
  };
  vi.stubGlobal("navigator", { onLine: true, locks });
}

/** A missing completion is an execution failure, not a behavioral assertion.
 * No fixed delay or wait timeout can establish a mutation kill here. */
async function producerCompletion(label: string, ready: () => boolean): Promise<void> {
  const deadline = Date.now() + 15_000;
  while (!ready()) {
    if (Date.now() >= deadline) throw new Error(`ExecutionError: producer completion timed out: ${label}`);
    await act(async () => { await new Promise<void>((resolve) => setTimeout(resolve, 10)); });
  }
  await flush();
}

async function submitPublicForm(root: ReactTestRenderer, trace: TraceRow[], label: string): Promise<void> {
  // Drive the same form handler used by native Enter submission. Verify its
  // actual public action is enabled before dispatch; never invoke a withheld
  // disabled button handler or retained private Login closure.
  expect(isDisabled(root, SIGN_IN)).toBe(false);
  let prevented = false;
  await act(async () => {
    root.root.findByType("form").props.onSubmit({ preventDefault() { prevented = true; } });
  });
  expect(prevented).toBe(true);
  trace.push({ phase: label, at: Date.now() });
}

function check(assertion: () => void): void {
  { assertion();  }
}





const token = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  token: "synthetic-second-token", user_id: NEXT_OWNER,
  expires_in: 86_400, role: "user", ...overrides,
});

async function refusalFixture(name: string): Promise<Refusal> {
  if (name === "therapist-role") return {
    name, initialMutantId: "90", errorText: "use the therapist portal instead",
    token: token({ role: "therapist" }),
  };
  if (name === "invalid-user-id") return {
    name, initialMutantId: "98", errorText: "server sent an invalid response",
    token: token({ user_id: NEXT_OWNER + "f" }),
  };
  if (name === "unsupported-kdf") return {
    name, initialMutantId: "132", errorText: "this browser cannot derive",
    token: token({ key_scheme: "v2" }),
    envelope: {
      key_scheme: "v2", salt: SALT,
      kdf_params: { algorithm: "argon2id", version: 1, iterations: 3, memory_kib: 65_536, parallelism: 1 },
      wrapped_data_key: toBase64(new Uint8Array(new ArrayBuffer(60))),
    },
  };
  if (name !== "authenticated-envelope-tamper") throw new Error(`Unknown refusal: ${name}`);
  const salt = fromBase64(SALT);
  const master = await deriveMasterKey(PASSWORD, salt);
  const envelope = await createRegistrationEnvelope(master, salt, NEXT_USERNAME);
  try {
    // Prove this is an authentic, correctly shaped envelope before corrupting
    // one ciphertext byte. The observed refusal is genuine AES-GCM failure,
    // rather than a malformed transport shape or a different account's AAD.
    const opened = await unwrapEnvelope(master, salt, NEXT_USERNAME, envelope.wrappedDataKeyB64, envelope.kdfParams);
    expect(opened).toEqual(envelope.dataKey);
    zeroize(opened);
    const bytes = fromBase64(envelope.wrappedDataKeyB64);
    expect(bytes).toHaveLength(60);
    bytes[20]! ^= 1;
    return {
      name, initialMutantId: "147", errorText: "key envelope could not be opened",
      token: token({ key_scheme: "v2" }),
      envelope: { key_scheme: "v2", salt: SALT, kdf_params: envelope.kdfParams, wrapped_data_key: toBase64(bytes) },
    };
  } finally { zeroize(master, envelope.dataKey); }
}

beforeEach(() => {
  vi.useRealTimers();
  resetTestState();
  applyLanguagePref("en");
});
afterEach(() => {
  resetTestState();
  vi.unstubAllGlobals();
});

describe("real App queued adoption followed by an enabled Login refusal", () => {
  it.each(["therapist-role", "invalid-user-id", "unsupported-kdf", "authenticated-envelope-tamper"])("%s erases the already adopted owner's keys before the queued App callback can run", async (name) => {
      const witness: Witness = { trace: [] };
      installFifoLocks(witness.trace);
      const gate = deferred();
      const admitted = deferred();
      // This holder represents another origin participant's supported
      // account-transition work. All application acquisitions still go
      // through the real platform.withLock and the FIFO request primitive.
      const holder = withLock("account-transition", async () => { admitted.resolve(); await gate.promise; });
      await admitted.promise;
      let root: ReactTestRenderer | undefined;
      let logins = 0;
      let envelopeRequests = 0;
      const unexpected: string[] = [];
      try {
        const refusal = await refusalFixture(name);

        stubFetch((url, init) => {
          witness.trace.push({ phase: `api:${url.split("/api/").at(-1)}`, at: Date.now() });
          if (url.endsWith("/auth/salt")) return jsonResponse({ salt: SALT });
          if (url.endsWith("/auth/login")) {
            logins += 1;
            const body = JSON.parse(String(init.body)) as { username?: string };
            if (logins === 1) {
              expect(body.username).toBe(FIRST_USERNAME);
              return jsonResponse(token({ token: "synthetic-first-token", user_id: FIRST_OWNER }));
            }
            expect(body.username).toBe(NEXT_USERNAME);
            return jsonResponse(refusal.token);
          }
          if (url.endsWith("/auth/key-envelope") && refusal.envelope) {
            envelopeRequests += 1;
            expect(new Headers(init.headers).get("Authorization")).toBe("Bearer synthetic-second-token");
            return jsonResponse(refusal.envelope);
          }
          unexpected.push(url);
          return jsonResponse({ code: "not_found" }, { status: 404 });
        });
        root = await render(<App />);
        await producerCompletion("App's boot timer renders real Login", () => buttonByLabel(root!, SIGN_IN));
        await typeInto(root, "Username", FIRST_USERNAME);
        await typeInto(root, "Password", PASSWORD);
        await submitPublicForm(root, witness.trace, "first-public-form-submit");
        await producerCompletion("first Login adopts real keys and releases busy", () =>
          logins === 1 && vault.isUnlocked() && buttonByLabel(root!, SIGN_IN) && !isDisabled(root!, SIGN_IN));
        const adopted = vault.get();
        const firstSignal = sessionAbortSignal();

        const accountRequests = () => witness.trace.filter(row => row.name === "account-transition" && row.phase === "lock-requested");
        const accountAdmissions = () => witness.trace.filter(row => row.name === "account-transition" && row.phase === "lock-admitted");
        check(() => {
          expect(vault.ownerUserId()).toBe(FIRST_OWNER);
          expect(sessionUserId()).toBe(FIRST_OWNER);
          expect(firstSignal?.aborted).toBe(false);
          expect(adopted.authKey.some(byte => byte !== 0)).toBe(true);
          expect(adopted.dataKey.some(byte => byte !== 0)).toBe(true);
        });
        check(() => {
          expect(accountRequests()).toHaveLength(2);
          expect(accountAdmissions()).toHaveLength(1);
          expect(root!.root.findAllByType("form")).toHaveLength(1);
          expect(isDisabled(root!, SIGN_IN)).toBe(false);
        });
        await typeInto(root, "Username", NEXT_USERNAME);
        // The real field/form remains mounted; the password is retained by
        // that very consumer, not installed through a session/vault helper.
        await submitPublicForm(root, witness.trace, "second-enabled-public-form-submit");
        await producerCompletion("second API response reaches the visible refusal and busy-finally", () =>
          logins === 2 && buttonByLabel(root!, SIGN_IN) && !isDisabled(root!, SIGN_IN)
          && textOf(root!).includes(refusal.errorText));



        {

{

          (() => { expect(logins).toBe(2); })();
          (() => { expect(envelopeRequests).toBe(refusal.envelope ? 1 : 0); })();
          (() => { expect(unexpected).toEqual([]); })();
          const alerts = root!.root.findAll(node => node.props.role === "alert");
          expect(alerts).toHaveLength(1);
          expect(textOfNode(alerts[0])).toContain(refusal.errorText);
          (() => { expect(accountRequests()).toHaveLength(2); })();
          (() => { expect(accountAdmissions()).toHaveLength(1); })();


}
}
        {

{

          expect(adopted.authKey.every(byte => byte === 0)).toBe(true);


}
}
        {

{

          expect(adopted.dataKey.every(byte => byte === 0)).toBe(true);


}
}
        {

{

          expect(vault.isUnlocked()).toBe(false);
          expect(vault.ownerUserId()).toBeNull();
          expect(hasSession()).toBe(false);
          expect(sessionUserId()).toBeNull();
          expect(firstSignal?.aborted).toBe(true);


}
}
        await act(async () => {
          gate.resolve();
          await holder;
          // A real FIFO sentinel follows the queued App producer, proving
          // that producer has completed instead of inferring from a delay.
          await withLock("account-transition", async () => {
            witness.trace.push({ phase: "after-queued-App-producer-barrier", at: Date.now() });
          });
        });
        await flush();


        {

{

          (() => { expect(accountAdmissions()).toHaveLength(3); })();
          expect(root!.root.findAllByType("form")).toHaveLength(1);
          expect(isDisabled(root!, SIGN_IN)).toBe(false);
          expect(textOf(root!)).toContain(refusal.errorText);
          expect(textOf(root!)).not.toContain("Step 1 of 3");
          expect(textOf(root!)).not.toContain("Today's entry");
          expect(vault.isUnlocked()).toBe(false);
          expect(hasSession()).toBe(false);


}
}

      }  finally {
        gate.resolve();
        await holder;
        await withLock("account-transition", async () => undefined);
        if (root) await act(async () => root!.unmount());

      }
    });

  it("pristine control: releasing the same queued real App adoption completes onboarding", async () => {
    const witness: Witness = { trace: [] };
    installFifoLocks(witness.trace);
    const gate = deferred();
    const admitted = deferred();
    const holder = withLock("account-transition", async () => { admitted.resolve(); await gate.promise; });
    await admitted.promise;
    let root: ReactTestRenderer | undefined;
    try {
      stubFetch(url => url.endsWith("/auth/salt") ? jsonResponse({ salt: SALT }) : jsonResponse(token({ token: "synthetic-first-token", user_id: FIRST_OWNER })));
      root = await render(<App />);
      await producerCompletion("control App boot", () => buttonByLabel(root!, SIGN_IN));
      await typeInto(root, "Username", FIRST_USERNAME);
      await typeInto(root, "Password", PASSWORD);
      await submitPublicForm(root, witness.trace, "control-public-form-submit");
      await producerCompletion("control Login releases busy while App waits", () =>
        vault.isUnlocked() && buttonByLabel(root!, SIGN_IN) && !isDisabled(root!, SIGN_IN));

      check(() => {
        expect(vault.ownerUserId()).toBe(FIRST_OWNER);
        expect(hasSession()).toBe(true);
        expect(witness.trace.filter(row => row.name === "account-transition" && row.phase === "lock-admitted")).toHaveLength(1);
      });
      await act(async () => {
        gate.resolve(); await holder;
        await withLock("account-transition", async () => undefined);
        // The actual lazy Onboarding consumer must settle before inspection.
        await import("../src/views/Onboarding");
      });
      await flush();


      {

{

        expect(textOf(root!)).toContain("Step 1 of 3");
        expect(root!.root.findAllByType("form")).toHaveLength(0);
        expect(vault.ownerUserId()).toBe(FIRST_OWNER);
        expect(hasSession()).toBe(true);


}
}

    }  finally {
      gate.resolve(); await holder;
      await withLock("account-transition", async () => undefined);
      if (root) await act(async () => root!.unmount());

    }
  });
});
