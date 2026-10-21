/** Weak Node Promise observation after actual public Login, password rotation,
 * and verified Unlock. No private production Map or source-text oracle. */
import crypto from "node:crypto";
import fs from "node:fs";
import { createHook } from "node:async_hooks";
import ReactTestRenderer, { act } from "react-test-renderer";
import { afterEach, expect, it, vi } from "vitest";
import { Text, TextInput, TouchableOpacity } from "react-native";
import { LoginScreen } from "../src/screens/LoginScreen";
import { UnlockScreen } from "../src/screens/UnlockScreen";
import { ThemeProvider } from "../src/theme";
import { SessionProvider, useSession } from "../src/store";
import { api, setBaseUrl } from "../src/api/client";
import { rotatePassword } from "../src/rotation";
import * as rekey from "../src/localRekey";
import { localKeyGeneration, localWriteScopeEpoch } from "../src/localWriteGuard";
import { vault } from "../src/vault";
import { emptySafetyPlan, loadSafetyPlan, saveSafetyPlan } from "../src/safetyPlan";
import { verifyUnlockProof } from "../src/unlockProof";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const USER = "c".repeat(32), NAME = "alice", FIRST_PASSWORD = "Retained Native password 2026!";
const TEXT = "My retained authored warning signs";
const ROTATIONS = 4;
const receiptFile = process.env.LOCAL_REKEY_TAIL_RETENTION_RECEIPT;
const gc = (globalThis as typeof globalThis & { gc?: () => void }).gc;
type Tag = { operation: string; epoch: number; generation: number; rotation: number };
type Allocation = Tag & { weak: WeakRef<object> };
const allocations: Allocation[] = [];
const controls = new Map<string, object>();
let current: Tag | undefined;
let rotation = 0;
let root: ReturnType<typeof ReactTestRenderer.create> | undefined;
let observation: Record<string, unknown> = {};
let factoryPromisesForwarded = 0;
let factoryIdentityCheck: (() => boolean) | undefined;
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
const observer = createHook({ init(_id, type, _trigger, resource) {
  if (current && type === "PROMISE" && resource && typeof resource === "object") {
    allocations.push({ ...current, weak: new WeakRef(resource) });
  }
} });
function save() { if (receiptFile) fs.writeFileSync(receiptFile, JSON.stringify(observation, null, 2) + "\n"); }
function setupFault(message: string): never {
  observation.stage = "setup-fault"; observation.setupFailure = message; save();
  throw new Error("SetupError: LocalRekeyRetentionSetupFault: " + message);
}
function requireSetup(value: unknown, message: string): asserts value { if (!value) setupFault(message); }
function answer(url: string, body: unknown, status = 200) {
  const result = new Response(JSON.stringify(body), { status }); Object.defineProperty(result, "url", { value: url }); return result;
}
function derive(password: string, salt: Buffer) {
  const master = crypto.pbkdf2Sync(password, salt, 600000, 32, "sha256");
  const label = (value: string) => Buffer.from(crypto.hkdfSync("sha256", master, Buffer.alloc(32), value, 32));
  const result = { auth: label("mindpattern/auth/v1"), data: label("mindpattern/data/v1") }; master.fill(0); return result;
}
function seal(key: Buffer, data: Buffer) {
  const nonce = crypto.randomBytes(12), cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(JSON.stringify(["entry", USER, "server-retained-entry"])));
  return Buffer.concat([nonce, cipher.update(data), cipher.final(), cipher.getAuthTag()]);
}
function open(key: Buffer, wire: Buffer) {
  const cipher = crypto.createDecipheriv("aes-256-gcm", key, wire.subarray(0, 12));
  cipher.setAAD(Buffer.from(JSON.stringify(["entry", USER, "server-retained-entry"]))); cipher.setAuthTag(wire.subarray(-16));
  return Buffer.concat([cipher.update(wire.subarray(12, -16)), cipher.final()]);
}
function State() {
  const session = useSession();
  if (session.authStatus !== "loggedIn") return <LoginScreen navigation={{ navigate: () => undefined }} />;
  return session.unlocked ? <Text>Verified native session ready</Text> : <UnlockScreen navigation={{ navigate: () => undefined }} />;
}
function input(label: string) {
  const node = root?.root.findAllByType(TextInput).find(candidate => candidate.props.accessibilityLabel === label);
  requireSetup(node, "the actual public input is absent: " + label); return node;
}
function button(label: string) {
  const node = root?.root.findAllByType(TouchableOpacity).find(candidate => candidate.props.accessibilityLabel === label);
  requireSetup(node, "the actual public primary action is absent: " + label); return node;
}
async function fill(label: string, value: string) { await act(async () => input(label).props.onChangeText(value)); }
async function publicCompletion(label: string) {
  const action = button(label); requireSetup(action.props.disabled !== true, "a required public action is disabled: " + label);
  await act(async () => {
    const pending: unknown = action.props.onPress();
    requireSetup(pending && typeof (pending as Promise<unknown>).then === "function", "the genuine public handler Promise is unavailable: " + label);
    await finite(pending as Promise<unknown>, label);
  });
  await act(async () => { await turn(); });
}
async function finite<T>(work: Promise<T>, stage: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([work, new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error("SetupError: LocalRekeyRetentionSetupFault: public producer deadline: " + stage)), 20000);
  })]); }
  finally { if (timer) clearTimeout(timer); }
}
function watchPublicFactories() {
  const phase = rekey.markLocalRekeyPhase, request = rekey.storeLocalRekeyRequest, tokens = rekey.storeLocalRekeyTokens;
  factoryIdentityCheck = () => rekey.markLocalRekeyPhase === phase && rekey.storeLocalRekeyRequest === request && rekey.storeLocalRekeyTokens === tokens;
  const around = <T,>(operation: string, work: () => T): T => {
    current = { operation, epoch: localWriteScopeEpoch(), generation: localKeyGeneration(USER), rotation };
    try {
      const originalPromise = work();
      requireSetup(originalPromise && typeof (originalPromise as unknown as Promise<unknown>).then === "function", "the original public journal factory did not return its Promise");
      const forwarded = originalPromise;
      requireSetup(forwarded === originalPromise, "the observed factory did not forward the original Promise unchanged");
      factoryPromisesForwarded++;
      return forwarded;
    } finally { current = undefined; }
  };
  vi.spyOn(rekey, "markLocalRekeyPhase").mockImplementation((...args) => around("markLocalRekeyPhase:" + args[1], () => phase(...args)));
  vi.spyOn(rekey, "storeLocalRekeyRequest").mockImplementation((...args) => around("storeLocalRekeyRequest", () => request(...args)));
  vi.spyOn(rekey, "storeLocalRekeyTokens").mockImplementation((...args) => around("storeLocalRekeyTokens", () => tokens(...args)));
  observer.enable();
}
function collectibleControl() { return new WeakRef(Promise.resolve()); }
async function collect() { await turn(); gc!(); await turn(); }
async function validateCollector(stage: string) {
  requireSetup(typeof gc === "function", "real Node --expose-gc is absent in the test fork");
  controls.set(stage, Promise.resolve());
  const positive = new WeakRef(controls.get(stage)!), negative = collectibleControl();
  for (let attempt = 0; attempt < 24; attempt++) {
    await collect();
    if (negative.deref() === undefined && positive.deref() === controls.get(stage)) {
      observation.collectorControls = [...(observation.collectorControls as unknown[] ?? []),
        { stage, attempts: attempt + 1, positiveRetained: true, negativeCollected: true }];
      controls.delete(stage); return;
    }
  }
  controls.delete(stage); setupFault("live/collectible Promise GC controls did not complete: " + stage);
}
async function publicRotations() {
  let password = FIRST_PASSWORD, nextPassword = "", salt = Buffer.alloc(16, 3), keys = derive(password, salt);
  let serverBlob = seal(keys.data, Buffer.from(TEXT)), bearer = "independently verified initial bearer", commits = 0;
  const tokens = new Map<string, Buffer>();
  const producerReceipts: Array<Record<string, unknown>> = [];
  vi.stubGlobal("fetch", async (url: string, init: RequestInit = {}) => {
    const route = new URL(url).pathname, body = init.body ? JSON.parse(String(init.body)) as Record<string, any> : {};
    const headers = new Headers(init.headers);
    if (route.endsWith("/auth/salt")) return answer(url, { salt: salt.toString("base64") });
    if (route.endsWith("/auth/key-envelope")) return answer(url, { key_scheme: "v1", salt: salt.toString("base64"), kdf_params: null, wrapped_data_key: null });
    if (route.endsWith("/auth/login")) return body.username === NAME && body.verifier === keys.auth.toString("base64")
      ? answer(url, { token: bearer, user_id: USER, role: "user" }) : answer(url, { code: "invalid_credentials" }, 401);
    if (route.endsWith("/processing/sessions")) {
      requireSetup(headers.get("Authorization") === "Bearer " + bearer, "processing request lacks its verified owner bearer");
      const token = "processing-" + rotation + "-" + tokens.size;
      tokens.set(token, Buffer.from(body.data_key, "base64")); return answer(url, { session_token: token });
    }
    if (route.endsWith("/processing/rekey")) {
      requireSetup(typeof body.operation_id === "string" && /^[0-9a-f-]{36}$/.test(body.operation_id), "actual rotation UUID is unavailable");
      requireSetup(headers.get("X-Account-Verifier") === keys.auth.toString("base64"), "atomic rotation lacks its old verifier");
      const old = tokens.get(headers.get("X-Processing-Token") ?? ""), next = tokens.get(headers.get("X-New-Processing-Token") ?? "");
      const newSalt = Buffer.from(body.new_salt, "base64"), successor = derive(nextPassword, newSalt);
      requireSetup(old?.equals(keys.data) && next?.equals(successor.data), "real old/new processing keys do not authenticate the server transition");
      requireSetup(newSalt.length === 16 && body.new_verifier === successor.auth.toString("base64"), "new credential proof is not independently derived");
      requireSetup(open(old!, serverBlob).toString() === TEXT, "actual old processing key cannot decrypt retained server ciphertext");
      serverBlob = seal(next!, Buffer.from(TEXT)); password = nextPassword; salt = newSalt;
      keys.auth.fill(0); keys.data.fill(0); keys = successor; bearer = "independently verified successor bearer " + ++commits;
      return answer(url, { credential_rotated: true, operation_id: body.operation_id, entries: 1, insights: 0, measures: 0, consents_rewrapped: 0, recovery_invalidated: false });
    }
    if (route.endsWith("/insights")) return answer(url, { active_days: 12 });
    if (route.endsWith("/meta")) return answer(url, { unlock_days: 30 });
    if (route.endsWith("/auth/logout")) return answer(url, {});
    if (route.endsWith("/consents")) return answer(url, []);
    setupFault("unexpected public producer route: " + route);
  });
  await api.clearSession(); await setBaseUrl("http://localhost:8000");
  await act(async () => { root = ReactTestRenderer.create(<ThemeProvider><SessionProvider><State /></SessionProvider></ThemeProvider>); });
  await act(async () => { await turn(); });
  await fill("Username", NAME); await fill("Password", password); await publicCompletion("Sign in");
  requireSetup(vault.isUnlocked() && vault.ownerUserId() === USER && vault.get().dataKey.equals(keys.data), "actual Login did not install independently derived v1 data key");
  const initialLoginCompleted = true;
  await saveSafetyPlan(vault.get().dataKey, USER, { ...emptySafetyPlan(), warningSigns: TEXT });
  watchPublicFactories();
  for (rotation = 1; rotation <= ROTATIONS; rotation++) {
    nextPassword = "Changed Native passphrase rotation " + rotation + " 2026!";
    const beforeEpoch = localWriteScopeEpoch(), beforeGeneration = localKeyGeneration(USER);
    let outcome: Awaited<ReturnType<typeof rotatePassword>> | undefined;
    await act(async () => { outcome = await finite(rotatePassword({ username: NAME, userId: USER, oldPassword: password, newPassword: nextPassword }), "rotation " + rotation); });
    requireSetup(outcome?.ok && outcome.scheme === "v1" && commits === rotation && !vault.isUnlocked(), "actual finite atomic rotation did not complete and lock");
    requireSetup(!await rekey.pendingLocalRekey(USER), "completed rotation still has an active checkpoint");
    await act(async () => { await turn(); });
    await fill("Password", password); await publicCompletion("Unlock");
    requireSetup(vault.isUnlocked() && vault.ownerUserId() === USER && vault.get().dataKey.equals(keys.data), "actual successor Unlock did not adopt its independently derived key");
    requireSetup(await verifyUnlockProof(keys.data, USER) === "ok", "actual successor offline proof is unusable");
    requireSetup((await loadSafetyPlan(keys.data, USER))?.warningSigns === TEXT && open(keys.data, serverBlob).toString() === TEXT, "successor local/server ciphertext is not independently readable");
    const epoch = localWriteScopeEpoch(), generation = localKeyGeneration(USER);
    requireSetup(epoch > beforeEpoch && generation > beforeGeneration, "legitimate rotation did not advance its public ownership/generation scope");
    producerReceipts.push({ rotation, beforeEpoch, beforeGeneration, epoch, generation, committed: true, independentlyVerifiedServerProof: true, actualSuccessorUnlock: true, retainedLocalContent: true });
  }
  observer.disable(); current = undefined;
  requireSetup(root, "the actual public renderer is absent before unmount");
  await act(async () => { root!.unmount(); root = undefined; });
  const actualRendererUnmountCompleted = root === undefined;
  tokens.clear(); keys.auth.fill(0); keys.data.fill(0); serverBlob.fill(0);
  // Vitest's spy registry stores each actual returned Promise in mock.results.
  // Remove that diagnostic custody before collection; the production journal
  // Map remains untouched and is the only authored tail owner under review.
  vi.clearAllMocks();
  vi.restoreAllMocks(); vi.unstubAllGlobals(); vault.lock(); await api.clearSession();
  const observerRestoredBeforeCollection = factoryIdentityCheck?.() === true && current === undefined;
  requireSetup(observerRestoredBeforeCollection, "the actual public factory observers were not restored before collection");
  requireSetup(factoryPromisesForwarded >= ROTATIONS * 4, "the unchanged actual public factory Promises were not observed in all four rotations");
  observation.observerRestoredBeforeCollection = observerRestoredBeforeCollection;
  observation.actualRendererUnmountCompleted = actualRendererUnmountCompleted;
  observation.originalFactoryPromisesForwardedUnchanged = true;
  observation.originalFactoryPromisesForwarded = factoryPromisesForwarded;
  observation.publicProducer = { complete: true, initialLoginCompleted, rotations: producerReceipts, atomicCommits: commits };
}
afterEach(() => { observer.disable(); current = undefined; controls.clear(); vi.restoreAllMocks(); vi.unstubAllGlobals(); save(); });

it("completed public rotations release settled journal factory Promise allocations across successor generations", async () => {
  observation = { stage: "collector-setup", nodeVersion: process.version, gcCapability: typeof gc === "function", collectorControls: [],
    evidenceClass: "Node host Promise retention after actual public Login/rotation/Unlock", limits: ["No private journalMutations Map inspection.", "Actual unchanged public factory calls observed weakly; promises/resources are not retained strongly by the observer.", "Injected native/HTTP transports and independent Node cryptography; no Android/iOS heap or hardware OOM proof."] };
  await validateCollector("before-public-producer");
  await publicRotations();
  const scopeTags = [...new Set(allocations.map(value => `${value.epoch}\0${value.generation}`))];
  requireSetup(scopeTags.length >= ROTATIONS && allocations.length >= ROTATIONS * 12, "actual public journal factory allocations were not observed across four scopes");
  requireSetup(new Set(allocations.map(value => value.operation)).size === 4, "actual server/credential/request/tokens journal calls were not observed");
  observation.capturedPromiseAllocations = allocations.length; observation.distinctGenerationScopes = scopeTags.length;
  observation.observedFactoryTags = [...new Set(allocations.map(value => value.operation))].sort();
  const allocationScopes = new Map<string, { rotation: number; epoch: number; generation: number; count: number; factoryCounts: Record<string, number> }>();
  for (const value of allocations) {
    const key = `${value.rotation}\0${value.epoch}\0${value.generation}`;
    let scope = allocationScopes.get(key);
    if (!scope) { scope = { rotation: value.rotation, epoch: value.epoch, generation: value.generation, count: 0, factoryCounts: {} }; allocationScopes.set(key, scope); }
    scope.count++; scope.factoryCounts[value.operation] = (scope.factoryCounts[value.operation] ?? 0) + 1;
  }
  observation.allocationScopes = [...allocationScopes.values()];
  observation.stage = "collector-after-public-producer"; await validateCollector("after-public-producer");
  for (let attempt = 0; attempt < 24; attempt++) { await collect(); if (allocations.every(value => value.weak.deref() === undefined)) break; }
  const retained = allocations.filter(value => value.weak.deref() !== undefined);
  observation.stage = "behavior-resource-assertion"; observation.retainedPromiseCount = retained.length;
  observation.retainedFactories = retained.map(({ operation, epoch, generation, rotation: observedRotation }) => ({ operation, epoch, generation, rotation: observedRotation })); save();
  expect(retained.length).toBe(0);
  observation.stage = "passed"; save();
}, 60000);
