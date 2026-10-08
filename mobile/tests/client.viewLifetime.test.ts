import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, ApiError, setBaseUrl } from "../src/api/client";
import { setSecureStoreBackend } from "../src/secureStore";
import storage from "./helpers/storageMock";
import * as keychain from "./helpers/keychainMock";
import { runTestControl } from "./helpers/testControl";

const USER = "abababababababababababababababab";
const KEY = Buffer.alloc(32, 79).toString("base64");
const ORIGIN = "https://native-view.example";
const deliveries: string[] = [];
const releases: Array<() => void> = [];

function response(): Response {
  const value = new Response(JSON.stringify({ session_token: "native processing receipt" }));
  Object.defineProperty(value, "url", { value: `${ORIGIN}/api/v1/processing/sessions` });
  return value;
}

function hold() {
  let entered = false;
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  releases.push(release);
  return { entered: () => entered, release, run: async () => { entered = true; await pending; } };
}

beforeEach(async () => {
  vi.restoreAllMocks();
  storage.__reset();
  keychain.__reset();
  runTestControl(setSecureStoreBackend, null);
  deliveries.length = 0;
  await setBaseUrl(ORIGIN);
  await api.setSession("actual Native bearer", USER, "alice");
  vi.stubGlobal("fetch", vi.fn(async (_url: unknown, init: RequestInit) => {
    deliveries.push(JSON.parse(String(init.body)).data_key);
    return response();
  }));
});

afterEach(async () => {
  for (const release of releases.splice(0)) release();
  vi.restoreAllMocks();
  await api.clearSession();
  vi.unstubAllGlobals();
});

it.each([
  ["first origin", "@mindpattern/base_url", 1],
  ["request origin", "@mindpattern/base_url", 2],
  ["bearer", "@mindpattern/token", 1],
  ["bearer owner", "@mindpattern/user_id", 1],
  ["bearer username", "@mindpattern/username", 1],
] as const)("retired view refuses key shipment after Native %s delivery", async (_label, slot, occurrence) => {
  const held = hold(), get = storage.getItem.bind(storage);
  let seen = 0, current = true;
  // Only the Native raw store is held; actual sealed credential decoding,
  // request ownership and dispatch execute unchanged.
  vi.spyOn(storage, "getItem").mockImplementation(async key => {
    const value = await get(key);
    if (key === slot && ++seen === occurrence) await held.run();
    return value;
  });
  const pending = api.openProcessingSession(KEY, undefined, () => current).catch((error: unknown) => error);
  await vi.waitFor(() => expect(held.entered()).toBe(true));
  current = false;
  held.release();
  const error = await pending;
  expect(error).toBeInstanceOf(ApiError);
  expect(error).toMatchObject({ status: 0, code: "stale_operation" });
  expect(deliveries).toEqual([]);
});

it("retired view refuses processing admission before any Native delivery", async () => {
  await expect(api.openProcessingSession(KEY, undefined, () => false)).rejects.toMatchObject({ status: 0, code: "stale_operation" });
  expect(deliveries).toEqual([]);
});

it("an unbound transition key cannot follow a replacement credential while its first origin read is pending", async () => {
  const held = hold(), get = storage.getItem.bind(storage);
  let first = true;
  vi.spyOn(storage, "getItem").mockImplementation(async key => {
    const value = await get(key);
    if (first && key === "@mindpattern/base_url") { first = false; await held.run(); }
    return value;
  });
  // Rotation/recovery can intentionally ship independent keys without an
  // ordinary local write permit; their captured origin still has to hold.
  const pending = api.openProcessingSession(KEY).catch((error: unknown) => error);
  await vi.waitFor(() => expect(held.entered()).toBe(true));
  await setBaseUrl("https://replacement-native.example");
  await api.setSession("replacement Native bearer", USER, "alice");
  held.release();
  expect(await pending).toMatchObject({ status: 0, code: "stale_operation" });
  expect(deliveries).toEqual([]);
});

it("a retired processing admission cannot occupy the Native storage queue ahead of a current view", async () => {
  const held = hold(), get = storage.getItem.bind(storage);
  let obsoleteDelivery = true, lane: Promise<unknown> = Promise.resolve();
  // Android AsyncStorage serializes native reads. An obsolete admission
  // must stop before it can park that provider and block a current caller.
  vi.spyOn(storage, "getItem").mockImplementation(key => {
    const obsolete = obsoleteDelivery;
    const pending = lane.then(async () => {
      const value = await get(key);
      if (obsolete && key === "@mindpattern/base_url") await held.run();
      return value;
    });
    lane = pending.then(() => {}, () => {});
    return pending;
  });
  const old = api.openProcessingSession(KEY, undefined, () => false).catch((error: unknown) => error);
  for (let i = 0; i < 8; i++) await Promise.resolve();
  obsoleteDelivery = false;
  const current = api.openProcessingSession(KEY, undefined, () => true).catch((error: unknown) => error);
  try {
    await vi.waitFor(() => expect(deliveries).toEqual([KEY]), { timeout: 1500 });
    expect(await current).toEqual({ session_token: "native processing receipt" });
  } finally {
    held.release();
    await Promise.all([old, current]);
  }
});

it.each(["headers", "body"] as const)("a retired view cannot adopt a processing receipt after Native %s delivery", async stage => {
  const held = hold();
  let current = true;
  vi.stubGlobal("fetch", vi.fn(async (_url: unknown, init: RequestInit) => {
    deliveries.push(JSON.parse(String(init.body)).data_key);
    if (stage === "headers") await held.run();
    const value = response();
    if (stage === "body") {
      const json = value.json.bind(value);
      vi.spyOn(value, "json").mockImplementation(async () => {
        const result = await json();
        await held.run();
        return result;
      });
    }
    return value;
  }));
  const pending = api.openProcessingSession(KEY, undefined, () => current).catch((error: unknown) => error);
  await vi.waitFor(() => expect(held.entered()).toBe(true));
  expect(deliveries).toEqual([KEY]);
  current = false;
  held.release();
  expect(await pending).toMatchObject({ status: 0, code: "stale_operation" });
});

it("a late Native processing response retains the already elapsed header timeout", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  let arrived = false, release: () => void = () => {};
  vi.stubGlobal("fetch", vi.fn((_url: unknown, init: RequestInit) => {
    arrived = true;
    return new Promise<Response>((resolve, reject) => {
      release = () => resolve(response());
      init.signal!.addEventListener("abort", () => {
        const error = new Error("Native request was aborted");
        error.name = "AbortError";
        reject(error);
      }, { once: true });
    });
  }));
  const pending = api.openProcessingSession(KEY, undefined, () => true).catch((error: unknown) => error);
  try {
    for (let i = 0; i < 128; i++) await Promise.resolve();
    expect(arrived).toBe(true);
    await vi.advanceTimersByTimeAsync(20000);
    release();
    expect(await pending).toMatchObject({ status: 0, message: "request timed out after 15s" });
  } finally {
    release();
    await pending;
    vi.useRealTimers();
  }
});

it.each([
  ["origin", "@mindpattern/base_url"],
  ["bearer", "@mindpattern/token"],
  ["bearer owner", "@mindpattern/user_id"],
  ["bearer username", "@mindpattern/username"],
] as const)("retired view refuses feedback shipment after Native recompute %s delivery", async (_label, slot) => {
  const held = hold(), get = storage.getItem.bind(storage);
  let current = true, first = true;
  vi.spyOn(storage, "getItem").mockImplementation(async key => {
    const value = await get(key);
    if (first && key === slot) { first = false; await held.run(); }
    return value;
  });
  const pending = api.recompute("current processing token", "sealed pending feedback", () => current).catch((error: unknown) => error);
  await vi.waitFor(() => expect(held.entered()).toBe(true));
  current = false;
  held.release();
  expect(await pending).toMatchObject({ status: 0, code: "stale_operation" });
  expect(deliveries).toEqual([]);
});

it("retired view refuses recompute admission before any Native delivery", async () => {
  await expect(api.recompute("current processing token", "sealed pending feedback", () => false)).rejects.toMatchObject({ status: 0, code: "stale_operation" });
  expect(deliveries).toEqual([]);
});

it.each(["headers", "body"] as const)("a retired view cannot adopt recompute after Native %s delivery", async stage => {
  const held = hold();
  let current = true;
  vi.stubGlobal("fetch", vi.fn(async (url: unknown, init: RequestInit) => {
    deliveries.push(JSON.parse(String(init.body)).feedback_blob);
    expect(new URL(String(url)).pathname).toBe("/api/v1/insights/recompute");
    expect(init.headers).toMatchObject({ "X-Processing-Token": "current processing token" });
    if (stage === "headers") await held.run();
    const value = new Response(JSON.stringify({ active_days: 8 }));
    Object.defineProperty(value, "url", { value: String(url) });
    if (stage === "body") {
      const json = value.json.bind(value);
      vi.spyOn(value, "json").mockImplementation(async () => {
        const result = await json();
        await held.run();
        return result;
      });
    }
    return value;
  }));
  const pending = api.recompute("current processing token", "sealed pending feedback", () => current).catch((error: unknown) => error);
  await vi.waitFor(() => expect(held.entered()).toBe(true));
  expect(deliveries).toEqual(["sealed pending feedback"]);
  current = false;
  held.release();
  expect(await pending).toMatchObject({ status: 0, code: "stale_operation" });
});

it("Native body timeout settles a processing caller even when its Response reader ignores abort", async () => {
  const held = hold();
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  vi.stubGlobal("fetch", vi.fn(async () => {
    const value = response(), json = value.json.bind(value);
    vi.spyOn(value, "json").mockImplementation(async () => {
      const result = await json();
      await held.run();
      return result;
    });
    return value;
  }));
  let settled = false, result: unknown;
  api.openProcessingSession(KEY, undefined, () => true).then(value => { settled = true; result = value; }, error => { settled = true; result = error; });
  try {
    for (let i = 0; i < 128; i++) await Promise.resolve();
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(20000);
    expect(settled).toBe(true);
    expect(result).toMatchObject({ status: 0, message: "request timed out after 15s" });
  } finally {
    held.release();
    for (let i = 0; i < 32; i++) await Promise.resolve();
    vi.useRealTimers();
  }
});

const settingsRequests = [
  ["create recovery", (current: () => boolean) => api.setupRecoveryKit("password proof", "recovery proof", "wrapped data key", "v2", current)],
  ["remove recovery", (current: () => boolean) => api.removeRecoveryKit("password proof", current)],
  ["LLM consent", (current: () => boolean) => api.setLlmConsent(true, "password proof", current)],
  ["voice consent", (current: () => boolean) => api.setVoiceConsent(true, "password proof", current)],
  ["delete account", (current: () => boolean) => api.deleteAccount("password proof", current)],
] as const;

const readRequests = [
  ["insights", (current: () => boolean) => api.insights(current)],
  ["today's question", (current: () => boolean) => api.questionToday(current)],
] as const;

it.each(readRequests.flatMap(([label, request]) => [
  [label, request, "@mindpattern/token", "@mindpattern/user_id"],
  [label, request, "@mindpattern/user_id", "@mindpattern/username"],
] as const))("an obsolete %s %s completion leaves the serial Native provider available to the current read", async (_label, request, pausedSlot, followingSlot) => {
  const completedRead = hold(), obsoleteRead = hold(), get = storage.getItem.bind(storage);
  let first = true, oldCurrent = true, obsoleteWindow = false;
  let lane: Promise<unknown> = Promise.resolve();
  vi.stubGlobal("fetch", async (url: unknown) => {
    deliveries.push(new URL(String(url)).pathname);
    const value = new Response(JSON.stringify({ active_days: 8, question: "current question" }));
    Object.defineProperty(value, "url", { value: String(url) });
    return value;
  });
  vi.spyOn(storage, "getItem").mockImplementation(key => {
    const expiredDispatch = obsoleteWindow && key === followingSlot;
    const pending = lane.then(async () => {
      const value = await get(key);
      if (first && key === pausedSlot) { first = false; await completedRead.run(); }
      if (expiredDispatch) await obsoleteRead.run();
      return value;
    });
    lane = pending.then(() => {}, () => {});
    return pending;
  });
  const old = request(() => oldCurrent).catch((error: unknown) => error);
  await vi.waitFor(() => expect(completedRead.entered()).toBe(true));
  oldCurrent = false; obsoleteWindow = true; completedRead.release();
  for (let i = 0; i < 32; i++) await Promise.resolve();
  obsoleteWindow = false;
  const current = request(() => true);
  try {
    await vi.waitFor(() => expect(deliveries).toHaveLength(1), { timeout: 1500 });
    expect(await current).toEqual({ active_days: 8, question: "current question" });
  } finally {
    completedRead.release(); obsoleteRead.release();
    await Promise.all([old, current]);
  }
});

it.each(readRequests.flatMap(([label, request]) => [
  [label, request, "admission", null],
  [label, request, "origin", "@mindpattern/base_url"],
  [label, request, "bearer", "@mindpattern/token"],
  [label, request, "owner", "@mindpattern/user_id"],
  [label, request, "username", "@mindpattern/username"],
] as const))("retired %s read refuses dispatch after Native %s delivery", async (_label, request, stage, slot) => {
  const held = hold(), get = storage.getItem.bind(storage);
  let current = stage !== "admission", first = true;
  vi.stubGlobal("fetch", async (url: unknown) => {
    deliveries.push(new URL(String(url)).pathname);
    const value = new Response(JSON.stringify({ active_days: 8, question: "current question" }));
    Object.defineProperty(value, "url", { value: String(url) });
    return value;
  });
  vi.spyOn(storage, "getItem").mockImplementation(async key => {
    const value = await get(key);
    if (first && key === slot) { first = false; await held.run(); }
    return value;
  });
  const pending = request(() => current).catch((error: unknown) => error);
  if (slot !== null) {
    await vi.waitFor(() => expect(held.entered()).toBe(true));
    current = false;
    held.release();
  }
  expect(await pending).toMatchObject({ status: 0, code: "stale_operation" });
  expect(deliveries).toEqual([]);
});

it.each(readRequests.flatMap(([label, request]) => [
  [label, request, "headers"], [label, request, "body"],
] as const))("a retired %s read cannot adopt Native %s delivery", async (_label, request, stage) => {
  const held = hold(); let current = true;
  vi.stubGlobal("fetch", async (url: unknown) => {
    deliveries.push(new URL(String(url)).pathname);
    if (stage === "headers") await held.run();
    const value = new Response(JSON.stringify({ active_days: 8, question: "current question" }));
    Object.defineProperty(value, "url", { value: String(url) });
    if (stage === "body") {
      const json = value.json.bind(value);
      vi.spyOn(value, "json").mockImplementation(async () => {
        const result = await json(); await held.run(); return result;
      });
    }
    return value;
  });
  const pending = request(() => current).catch((error: unknown) => error);
  await vi.waitFor(() => expect(held.entered()).toBe(true));
  current = false; held.release();
  expect(await pending).toMatchObject({ status: 0, code: "stale_operation" });
});

it.each(settingsRequests.flatMap(([label, request]) => [
  [label, request, "admission", null],
  [label, request, "origin", "@mindpattern/base_url"],
  [label, request, "bearer", "@mindpattern/token"],
  [label, request, "owner", "@mindpattern/user_id"],
  [label, request, "username", "@mindpattern/username"],
] as const))("retired Settings %s refuses sensitive dispatch after Native %s delivery", async (_label, request, stage, slot) => {
  const held = hold(), get = storage.getItem.bind(storage); let current = stage !== "admission", first = true;
  vi.stubGlobal("fetch", async (url: unknown) => {
    deliveries.push(new URL(String(url)).pathname);
    const value = new Response(JSON.stringify({ enabled: true, active_for_current_policy: true }));
    Object.defineProperty(value, "url", { value: String(url) }); return value;
  });
  vi.spyOn(storage, "getItem").mockImplementation(async key => {
    const value = await get(key); if (first && key === slot) { first = false; await held.run(); } return value;
  });
  const pending = request(() => current).catch((error: unknown) => error);
  if (stage !== "admission") { await vi.waitFor(() => expect(held.entered()).toBe(true)); current = false; held.release(); }
  expect(await pending).toMatchObject({ status: 0, code: "stale_operation" }); expect(deliveries).toEqual([]);
});
