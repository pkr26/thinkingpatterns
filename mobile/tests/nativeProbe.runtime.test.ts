import { runTestControl } from "./helpers/testControl";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Module from "node:module";

// Metro's synchronous require resolves linked native modules before the
// optional import fallback. Exercise that production route in this process.
vi.mock("react-native-health", () => { throw new Error("native module absent"); });
vi.mock("@notifee/react-native", () => { throw new Error("native module absent"); });

const healthApi = () => ({
  requestAuthorization: vi.fn(async () => true),
  getAuthorizationStatus: vi.fn(async () => ({ stateOfMind: 2 })),
  saveStateOfMind: vi.fn(async () => true),
});

async function linked(health: unknown = healthApi(), notifications: unknown = {}) {
  const loader = Module as unknown as { _load: (name: string, ...args: unknown[]) => unknown };
  const original = loader._load;
  const requireNative = vi.spyOn(loader, "_load").mockImplementation((name: string, ...args: unknown[]) => {
    if (name === "react-native-health") return health;
    if (name === "@notifee/react-native") return notifications;
    return original.call(Module, name, ...args);
  });
  const native = await import("../src/nativeFeatures");
  const healthkit = await import("../src/healthkit");
  const { Platform } = await import("react-native");
  const route = await import("../src/notificationRoute");
  route.takePendingNotificationRoute();
  return { native, healthkit, requireNative, Platform: Platform as unknown as { OS: string; Version: string | number }, route };
}

beforeEach(() => { vi.resetModules(); });
afterEach(() => {
  vi.restoreAllMocks(); vi.unstubAllGlobals();
  vi.doMock("@notifee/react-native", () => { throw new Error("native module absent"); });
});

describe("linked synchronous native capability probes", () => {
  it("recognizes linked HealthKit and notifications instead of reporting an absent module", async () => {
    const { healthkit, native, Platform, requireNative } = await linked();
    Platform.OS = "ios"; Platform.Version = 18;
    expect(healthkit.healthKitCapability()).toEqual({ available: true });
    expect(native.reminderCapability()).toEqual({ available: true });
    expect(requireNative.mock.calls.some(([name]) => name === "react-native-health")).toBe(true);
    expect(requireNative.mock.calls.some(([name]) => name === "@notifee/react-native")).toBe(true);
  });

  it.each([17, 17.99, "17", "17.99"])("reports the system requirement for iOS %s", async (version) => {
    const { healthkit, Platform } = await linked();
    Platform.OS = "ios"; Platform.Version = version;
    expect(healthkit.healthKitCapability()).toEqual({ available: false, reason: "settings.reasonHealthIOS18" });
  });

  it.each([18, 18.5, "18", "18.5", "unknown"])("accepts linked capable modules at iOS version %s", async (version) => {
    const { healthkit, Platform } = await linked();
    Platform.OS = "ios"; Platform.Version = version;
    expect(healthkit.healthKitCapability()).toEqual({ available: true });
  });

  it("applies the iOS version requirement only to iOS", async () => {
    const { healthkit, Platform } = await linked();
    Platform.OS = "android"; Platform.Version = 17;
    expect(healthkit.healthKitCapability()).toEqual({ available: true });
  });

  it.each([{}, { default: {} }, { requestAuthorization: () => true }, { saveStateOfMind: () => true }])(
    "distinguishes linked modules lacking the State of Mind API", async (module) => {
      const { healthkit, Platform } = await linked(module);
      Platform.OS = "ios"; Platform.Version = 18;
      expect(healthkit.healthKitCapability()).toEqual({ available: false, reason: "settings.reasonHealthOldModule" });
    },
  );

  it("handles both native direct exports and their default-export wrapper", async () => {
    const api = healthApi();
    const { healthkit, Platform } = await linked({ default: api });
    Platform.OS = "ios"; Platform.Version = 18;
    expect(healthkit.healthKitCapability()).toEqual({ available: true });
    expect(await healthkit.ensureStateOfMindWriteAccess()).toBe(true);
    expect(api.requestAuthorization).toHaveBeenCalledWith({ stateOfMind: { write: true } });
  });

  it("reports truly absent native modules and declines their actions", async () => {
    const { healthkit, native } = await linked(null, null);
    expect(healthkit.healthKitCapability()).toEqual({ available: false, reason: "settings.reasonHealthModule" });
    expect(native.reminderCapability()).toEqual({ available: false, reason: "settings.reasonNotifModule" });
    expect(await healthkit.ensureStateOfMindWriteAccess()).toBe(false);
    expect(await healthkit.writeStateOfMind(0, "2026-10-05")).toBe(false);
    expect(await native.startNotificationPressRouting()).toBeNull();
  });

  it.each([3, "linked", true, { default: 3 }, { default: "linked" }, { default: true }])(
    "declines malformed linked HealthKit exports without rejecting", async (module) => {
      const { healthkit } = await linked(module);
      expect(healthkit.healthKitCapability()).toEqual({ available: false, reason: "settings.reasonHealthOldModule" });
      expect(await healthkit.ensureStateOfMindWriteAccess()).toBe(false);
      expect(await healthkit.writeStateOfMind(0, "2026-10-05")).toBe(false);
    },
  );

  it.each([false, true])("validates an object API even when a callable carries native methods (wrapped=%s)", async (wrapped) => {
    const callable = Object.assign(() => undefined, healthApi());
    const { healthkit } = await linked(wrapped ? { default: callable } : callable);
    expect(healthkit.healthKitCapability()).toEqual({ available: false, reason: "settings.reasonHealthOldModule" });
    expect(await healthkit.ensureStateOfMindWriteAccess()).toBe(false);
    expect(callable.requestAuthorization).not.toHaveBeenCalled();
  });

  it("declines a callable HealthKit package even when it carries an object default export", async () => {
    const api = healthApi();
    const { healthkit } = await linked(Object.assign(() => undefined, { default: api }));
    expect(healthkit.healthKitCapability()).toEqual({ available: false, reason: "settings.reasonHealthOldModule" });
    expect(await healthkit.ensureStateOfMindWriteAccess()).toBe(false);
    expect(api.requestAuthorization).not.toHaveBeenCalled();
  });

  it("allows capable older modules whose optional authorization-status method is absent", async () => {
    const api = healthApi();
    delete (api as Partial<typeof api>).getAuthorizationStatus;
    const { healthkit } = await linked(api);
    expect(await healthkit.ensureStateOfMindWriteAccess()).toBe(true);
    expect(await healthkit.writeStateOfMind(0, "2026-10-05")).toBe(true);
    expect(api.saveStateOfMind).toHaveBeenCalledOnce();
  });

  it.each([undefined, null, 1, true, "denied"]) ("ignores malformed optional status %s and lets the native save decide", async (status) => {
    const api = healthApi();
    api.getAuthorizationStatus.mockResolvedValue(status as never);
    const { healthkit } = await linked(api);
    expect(await healthkit.ensureStateOfMindWriteAccess()).toBe(true);
    expect(await healthkit.writeStateOfMind(0, "2026-10-05")).toBe(true);
  });

  it("refuses an initially retired mirror operation even if account eligibility changes during a later read", async () => {
    const api = healthApi();
    const { healthkit } = await linked(api);
    const storage = (await import("./helpers/storageMock")).default;
    const lifecycle = await import("../src/localWriteGuard");
    runTestControl(lifecycle.__resetLocalKeyLifecycleForTests); lifecycle.changeLocalSessionOwner("owner");
    storage.__reset(); await healthkit.setMoodMirrorPref("owner", true);
    let owned = false; let release: (() => void) | undefined; let paused = false;
    const original = storage.getItem.bind(storage);
    vi.spyOn(storage, "getItem").mockImplementation(async key => {
      const value = await original(key);
      if (!paused) { paused = true; await new Promise<void>(resolve => { release = resolve; }); }
      return value;
    });
    const pending = healthkit.mirrorMoodCheckIn("owner", 0, "2026-10-05", () => owned);
    await flush(); owned = true; release?.();
    expect(await pending).toBe(false);
    expect(api.requestAuthorization).not.toHaveBeenCalled();
    expect(api.saveStateOfMind).not.toHaveBeenCalled();
  });

  it("declines a write after the opt-in recheck reports disabled", async () => {
    const api = healthApi();
    const { healthkit } = await linked(api);
    expect(await healthkit.writeStateOfMind(0, "2026-10-05", () => true, async () => false)).toBe(false);
    expect(api.requestAuthorization).toHaveBeenCalledOnce();
    expect(api.saveStateOfMind).not.toHaveBeenCalled();
  });

  it("degrades a failing account-ownership callback to a quiet false", async () => {
    const api = healthApi();
    const { healthkit } = await linked(api);
    expect(await healthkit.mirrorMoodCheckIn("owner", 0, "2026-10-05", () => { throw new Error("retired"); })).toBe(false);
    expect(api.requestAuthorization).not.toHaveBeenCalled();
    expect(api.saveStateOfMind).not.toHaveBeenCalled();
  });

  it("does not resurrect an initially ineligible check-in when account eligibility returns on the next turn", async () => {
    const api = healthApi();
    const { healthkit } = await linked(api);
    const storage = (await import("./helpers/storageMock")).default;
    const lifecycle = await import("../src/localWriteGuard");
    runTestControl(lifecycle.__resetLocalKeyLifecycleForTests); lifecycle.changeLocalSessionOwner("owner");
    storage.__reset(); await healthkit.setMoodMirrorPref("owner", true);
    let eligible = false;
    const pending = healthkit.mirrorMoodCheckIn("owner", 0, "2026-10-05", () => eligible);
    queueMicrotask(() => { eligible = true; });
    expect(await pending).toBe(false);
    expect(api.requestAuthorization).not.toHaveBeenCalled();
    expect(api.saveStateOfMind).not.toHaveBeenCalled();
  });

  it.each(["disable", "clear"])("revokes the last in-flight preference read before native dispatch (%s)", async (operation) => {
    const api = healthApi();
    const { healthkit } = await linked(api);
    const storage = (await import("./helpers/storageMock")).default;
    const lifecycle = await import("../src/localWriteGuard");
    runTestControl(lifecycle.__resetLocalKeyLifecycleForTests); lifecycle.changeLocalSessionOwner("owner");
    storage.__reset();
    await healthkit.setMoodMirrorPref("owner", true);
    const original = storage.getItem.bind(storage);
    let reads = 0;
    let release!: () => void;
    let entered!: () => void;
    const held = new Promise<void>(resolve => { entered = resolve; });
    const read = vi.spyOn(storage, "getItem").mockImplementation(async key => {
      const value = await original(key);
      if (key === "@mindpattern/mirror_mood_to_health_owner" && ++reads === 2) {
        entered(); await new Promise<void>(resolve => { release = resolve; });
      }
      return value;
    });
    const pending = healthkit.mirrorMoodCheckIn("owner", 0, "2026-10-05");
    const reachedRead = await Promise.race([held.then(() => true), pending.then(() => false)]);
    expect(reachedRead).toBe(true);
    if (operation === "disable") await healthkit.setMoodMirrorPref("owner", false);
    else await healthkit.clearMoodMirrorPref("owner");
    release();
    expect(await pending).toBe(false);
    expect(api.saveStateOfMind).not.toHaveBeenCalled();
    expect(await healthkit.getMoodMirrorPref("owner")).toBe(false);
    read.mockRestore();
  });

  it("rejects a health write whose ownership was lost before native authorization", async () => {
    const api = healthApi();
    const { healthkit } = await linked(api);
    expect(await healthkit.writeStateOfMind(0, "2026-10-05", () => false)).toBe(false);
    expect(api.requestAuthorization).not.toHaveBeenCalled();
    expect(api.saveStateOfMind).not.toHaveBeenCalled();
  });

  it("rechecks ownership at the actual native sample dispatch boundary", async () => {
    const api = healthApi();
    const { healthkit } = await linked(api);
    const owner = vi.fn().mockReturnValueOnce(true).mockReturnValueOnce(false);
    expect(await healthkit.writeStateOfMind(0.5, "2026-10-05", owner)).toBe(false);
    expect(api.requestAuthorization).toHaveBeenCalledOnce();
    expect(api.saveStateOfMind).not.toHaveBeenCalled();
  });
});

type Tap = { type: number; detail?: { notification?: { id?: unknown } } };
const MEASURE_ID = "mindpattern-measure-reminder";

function eventApi(press?: number) {
  let handler: ((event: Tap) => void) | undefined;
  let resolveInitial!: (value: { notification?: { id?: unknown } } | null) => void;
  const unsubscribe = vi.fn();
  const getInitialNotification = vi.fn(() => new Promise<{ notification?: { id?: unknown } } | null>(resolve => { resolveInitial = resolve; }));
  const onForegroundEvent = vi.fn((next: (event: Tap) => void) => { handler = next; return unsubscribe; });
  return { module: { default: { getInitialNotification, onForegroundEvent }, ...(press === undefined ? {} : { EventType: { PRESS: press } }) },
    getInitialNotification, onForegroundEvent, unsubscribe, fire: (event: Tap) => { if (!handler) throw new Error("No native tap subscription"); handler(event); },
    initial: (value: { notification?: { id?: unknown } } | null) => resolveInitial(value) };
}

const flush = async () => { await Promise.resolve(); await Promise.resolve(); };

const schedulerApi = () => ({
  requestPermission: vi.fn(async () => ({ authorizationStatus: 1 })),
  createTriggerNotification: vi.fn(async (_notification: unknown, _trigger: unknown) => "created"),
  cancelAllNotifications: vi.fn(async () => undefined),
  cancelNotification: vi.fn(async () => undefined),
  createChannel: vi.fn(async () => "channel"),
});

async function scheduled(module: unknown) {
  const context = await linked(healthApi(), module);
  const lifecycle = await import("../src/localWriteGuard");
  runTestControl(lifecycle.__resetLocalKeyLifecycleForTests);
  lifecycle.changeLocalSessionOwner("owner");
  const ownership = await import("../src/notificationOwnership");
  const storage = (await import("./helpers/storageMock")).default;
  storage.__reset();
  return { ...context, ownership, lifecycle, storage };
}

describe("linked native scheduling surface", () => {
  it("sends the independent one-time measure payload and exact native enum", async () => {
    const api = schedulerApi();
    const { native, ownership } = await scheduled({ default: api, TriggerType: { TIMESTAMP: 7 }, RepeatFrequency: { DAILY: 8 } });
    const fire = new Date("2026-10-06T12:15:00Z");
    expect(await native.scheduleMeasureReminder(fire, ownership.beginNotificationUpdate("owner", "measure"))).toBe(true);
    expect(api.cancelNotification).toHaveBeenCalledWith(MEASURE_ID);
    expect(api.createTriggerNotification).toHaveBeenCalledWith({ id: MEASURE_ID, title: "Fathom", body: "A quiet moment for a wellbeing check-in, whenever it suits you.", android: { channelId: "mindpattern-reminders" } }, { type: 7, timestamp: fire.getTime() });
  });

  it("uses custom native enums and supports modules without optional channel creation", async () => {
    const api = schedulerApi();
    delete (api as Partial<typeof api>).createChannel;
    const { native, ownership } = await scheduled({ default: api, TriggerType: { TIMESTAMP: 7 }, RepeatFrequency: { DAILY: 8 } });
    expect(await native.scheduleDailyReminder(9, 15, ownership.beginNotificationUpdate("owner", "daily"))).toBe(true);
    expect(api.createTriggerNotification.mock.calls[0]?.[1]).toMatchObject({ type: 7, repeatFrequency: 8 });
  });

  it("falls back to timestamp and daily constants only when enums are missing", async () => {
    const api = schedulerApi();
    const { native, ownership } = await scheduled(api);
    expect(await native.scheduleDailyReminder(9, 15, ownership.beginNotificationUpdate("owner", "daily"))).toBe(true);
    expect(api.createTriggerNotification.mock.calls[0]?.[1]).toMatchObject({ type: 0, repeatFrequency: 1 });
  });

  it.each([null, {}, { default: {} }, { default: 3 }])("declines invalid scheduling modules for daily, measure and cancellation actions", async (module) => {
    const { native, ownership } = await scheduled(module);
    expect(await native.scheduleDailyReminder(9, 15, ownership.beginNotificationUpdate("owner", "daily"))).toBe(false);
    expect(await native.scheduleMeasureReminder(new Date(), ownership.beginNotificationUpdate("owner", "measure"))).toBe(false);
    expect(await native.cancelDailyReminder("owner")).toBe(false);
    expect(await native.cancelMeasureReminder()).toBe(false);
    expect(await native.cancelOriginNotifications()).toBe(true);
  });

  it.each([false, true])("declines callable scheduling exports even when they carry method properties (wrapped=%s)", async (wrapped) => {
    const api = Object.assign(() => undefined, schedulerApi());
    const { native, ownership } = await scheduled(wrapped ? { default: api } : api);
    expect(await native.scheduleDailyReminder(9, 15, ownership.beginNotificationUpdate("owner", "daily"))).toBe(false);
    expect(await native.cancelDailyReminder()).toBe(false);
    expect(api.requestPermission).not.toHaveBeenCalled();
    expect(api.cancelNotification).not.toHaveBeenCalled();
  });

  it("declines a callable notification package even when it carries an object default export", async () => {
    const api = schedulerApi();
    const { native, ownership } = await scheduled(Object.assign(() => undefined, { default: api }));
    expect(await native.scheduleDailyReminder(9, 15, ownership.beginNotificationUpdate("owner", "daily"))).toBe(false);
    expect(api.requestPermission).not.toHaveBeenCalled();
  });

  it("treats a null permission result as denied", async () => {
    const api = schedulerApi();
    api.requestPermission.mockResolvedValue(null as never);
    const { native, ownership } = await scheduled(api);
    expect(await native.scheduleDailyReminder(9, 15, ownership.beginNotificationUpdate("owner", "daily"))).toBe(false);
    expect(api.createTriggerNotification).not.toHaveBeenCalled();
  });

  it.each(["requestPermission", "createTriggerNotification", "cancelAllNotifications"] as const)("requires the declared scheduling API method %s", async (method) => {
    const api = schedulerApi();
    delete (api as Partial<typeof api>)[method];
    const { native, ownership } = await scheduled(api);
    expect(await native.scheduleDailyReminder(9, 15, ownership.beginNotificationUpdate("owner", "daily"))).toBe(false);
    expect(await native.cancelDailyReminder()).toBe(false);
    expect(api.cancelNotification).not.toHaveBeenCalled();
  });

  for (const kind of ["daily", "measure"] as const) {
    it.each(["permission", "cancel", "channel"] as const)(`${kind} cannot dispatch a following native operation after retirement at %s`, async (boundary) => {
      const api = schedulerApi();
      const { native, ownership, lifecycle } = await scheduled(api);
      let entered!: () => void;
      let release!: () => void;
      const reached = new Promise<void>(resolve => { entered = resolve; });
      const wait = new Promise<void>(resolve => { release = resolve; });
      if (boundary === "permission") api.requestPermission.mockImplementationOnce(async () => { entered(); await wait; return { authorizationStatus: 1 }; });
      if (boundary === "cancel") api.cancelNotification.mockImplementationOnce(async () => { entered(); await wait; });
      if (boundary === "channel") api.createChannel.mockImplementationOnce(async () => { entered(); await wait; return "channel"; });
      const owner = ownership.beginNotificationUpdate("owner", kind);
      const pending = kind === "daily" ? native.scheduleDailyReminder(9, 15, owner) : native.scheduleMeasureReminder(new Date(), owner);
      expect(await Promise.race([reached.then(() => true), pending.then(() => false)])).toBe(true);
      lifecycle.changeLocalSessionOwner("replacement"); release();
      expect(await pending).toBe(false);
      if (boundary === "permission") expect(api.cancelNotification).not.toHaveBeenCalled();
      if (boundary !== "channel") expect(api.createChannel).not.toHaveBeenCalled();
      expect(api.createTriggerNotification).not.toHaveBeenCalled();
    });

    it(`${kind} cancellation supersedes pending permission before it can dispatch`, async () => {
      const api = schedulerApi();
      const { native, ownership } = await scheduled(api);
      let entered!: () => void; let release!: () => void;
      const reached = new Promise<void>(resolve => { entered = resolve; });
      const wait = new Promise<void>(resolve => { release = resolve; });
      api.requestPermission.mockImplementationOnce(async () => { entered(); await wait; return { authorizationStatus: 1 }; });
      const owner = ownership.beginNotificationUpdate("owner", kind);
      const pending = kind === "daily" ? native.scheduleDailyReminder(9, 15, owner) : native.scheduleMeasureReminder(new Date(), owner);
      expect(await Promise.race([reached.then(() => true), pending.then(() => false)])).toBe(true);
      const cancellation = kind === "daily" ? native.cancelDailyReminder() : native.cancelMeasureReminder();
      release();
      expect(await pending).toBe(false);
      expect(await cancellation).toBe(true);
      expect(api.createTriggerNotification).not.toHaveBeenCalled();
    });

    it(`${kind} stops after a newer same-account preference supersedes permission`, async () => {
      const api = schedulerApi();
      const { native, ownership } = await scheduled(api);
      let entered!: () => void; let release!: () => void;
      const reached = new Promise<void>(resolve => { entered = resolve; });
      const wait = new Promise<void>(resolve => { release = resolve; });
      api.requestPermission.mockImplementationOnce(async () => { entered(); await wait; return { authorizationStatus: 1 }; });
      const owner = ownership.beginNotificationUpdate("owner", kind);
      const pending = kind === "daily" ? native.scheduleDailyReminder(9, 15, owner) : native.scheduleMeasureReminder(new Date(), owner);
      expect(await Promise.race([reached.then(() => true), pending.then(() => false)])).toBe(true);
      ownership.beginNotificationUpdate("owner", kind); release();
      expect(await pending).toBe(false);
      expect(api.cancelNotification).not.toHaveBeenCalled();
      expect(api.createTriggerNotification).not.toHaveBeenCalled();
    });
  }

  it("rejects a supplied cancellation or migration owner belonging to another account", async () => {
    const api = schedulerApi();
    const { native, ownership, storage } = await scheduled(api);
    const wrong = ownership.beginNotificationUpdate("owner", "daily");
    expect(await native.cancelDailyReminder("other", wrong)).toBe(false);
    await native.migrateOrphanedReminderNotifications("other", wrong);
    expect(api.cancelNotification).not.toHaveBeenCalled();
    expect(api.cancelAllNotifications).not.toHaveBeenCalled();
    expect(await storage.getItem("@mindpattern/reminder.migration.v2.done")).toBeNull();
  });

  it("a direct measure cancellation targets the independent stable id", async () => {
    const api = schedulerApi();
    const { native } = await scheduled(api);
    expect(await native.cancelMeasureReminder()).toBe(true);
    expect(api.cancelNotification).toHaveBeenCalledWith(MEASURE_ID);
    expect(api.cancelAllNotifications).not.toHaveBeenCalled();
  });

  it.each(["disabled", "no-baseline"] as const)("fallback daily cancellation does not ask permission for an ineligible measure reminder (%s)", async eligibility => {
    const api = schedulerApi(); delete (api as Partial<typeof api>).cancelNotification;
    const { native } = await scheduled(api);
    const measures = await import("../src/measureReminders");
    await measures.setMeasureReminderEnabled("owner", eligibility === "no-baseline");
    if (eligibility === "disabled") await measures.recordMeasureCompleted("owner", "2026-10-05");
    expect(await native.cancelDailyReminder("owner")).toBe(true);
    expect(api.cancelAllNotifications).toHaveBeenCalledOnce();
    expect(api.requestPermission).not.toHaveBeenCalled();
    expect(api.createTriggerNotification).not.toHaveBeenCalled();
  });

  it("fallback measure cancellation restores the enabled daily reminder", async () => {
    const api = schedulerApi(); delete (api as Partial<typeof api>).cancelNotification;
    const { native } = await scheduled(api);
    const reminders = await import("../src/reminders");
    await reminders.setReminderEnabled("owner", true);
    expect(await native.cancelMeasureReminder("owner")).toBe(true);
    expect(api.createTriggerNotification).toHaveBeenCalledOnce();
    expect(api.createTriggerNotification.mock.calls[0][0]).toMatchObject({ id: "mindpattern-daily-reminder" });
  });

  it("fallback cancellation cannot restore a sibling after a newer same-kind cancellation intent", async () => {
    const api = schedulerApi(); delete (api as Partial<typeof api>).cancelNotification;
    const { native, ownership } = await scheduled(api);
    const reminders = await import("../src/reminders");
    await reminders.setReminderEnabled("owner", true);
    let entered!: () => void; let release!: () => void;
    const reached = new Promise<void>(resolve => { entered = resolve; });
    const hold = new Promise<void>(resolve => { release = resolve; });
    api.cancelAllNotifications.mockImplementationOnce(async () => { entered(); await hold; });
    const pending = native.cancelMeasureReminder("owner");
    expect(await Promise.race([reached.then(() => true), pending.then(() => false)])).toBe(true);
    ownership.beginNotificationUpdate("owner", "measure"); release();
    expect(await pending).toBe(false);
    expect(api.requestPermission).not.toHaveBeenCalled();
    expect(api.createTriggerNotification).not.toHaveBeenCalled();
  });

  it("fallback daily cancellation cannot recreate a measure superseded during permission", async () => {
    const api = schedulerApi(); delete (api as Partial<typeof api>).cancelNotification;
    const { native, ownership } = await scheduled(api);
    const measures = await import("../src/measureReminders");
    await measures.setMeasureReminderEnabled("owner", true);
    await measures.recordMeasureCompleted("owner", "2026-10-05");
    let entered!: () => void; let release!: () => void;
    const reached = new Promise<void>(resolve => { entered = resolve; });
    const hold = new Promise<void>(resolve => { release = resolve; });
    api.requestPermission.mockImplementationOnce(async () => { entered(); await hold; return { authorizationStatus: 1 }; });
    const pending = native.cancelDailyReminder("owner");
    expect(await Promise.race([reached.then(() => true), pending.then(() => false)])).toBe(true);
    ownership.beginNotificationUpdate("owner", "measure"); release();
    expect(await pending).toBe(true);
    expect(api.createTriggerNotification).not.toHaveBeenCalled();
  });

  it.each(["admin", "origin"] as const)("a completed native %s cancellation reports retirement honestly", async operation => {
    const api = schedulerApi(); delete (api as Partial<typeof api>).cancelNotification;
    const { native, lifecycle } = await scheduled(api);
    let entered!: () => void; let release!: () => void;
    const reached = new Promise<void>(resolve => { entered = resolve; });
    const hold = new Promise<void>(resolve => { release = resolve; });
    api.cancelAllNotifications.mockImplementationOnce(async () => { entered(); await hold; });
    const pending = operation === "admin" ? native.cancelDailyReminder() : native.cancelOriginNotifications();
    expect(await Promise.race([reached.then(() => true), pending.then(() => false)])).toBe(true);
    lifecycle.changeLocalSessionOwner("replacement"); release();
    expect(await pending).toBe(false);
  });

  it.each(["daily", "measure"] as const)("origin cancellation retires a pending %s producer before native permission completes", async kind => {
    const api = schedulerApi(); const { native, ownership } = await scheduled(api);
    let entered!: () => void; let release!: () => void;
    const reached = new Promise<void>(resolve => { entered = resolve; });
    const hold = new Promise<void>(resolve => { release = resolve; });
    api.requestPermission.mockImplementationOnce(async () => { entered(); await hold; return { authorizationStatus: 1 }; });
    const owner = ownership.beginNotificationUpdate("owner", kind);
    const pending = kind === "daily" ? native.scheduleDailyReminder(9, 15, owner) : native.scheduleMeasureReminder(new Date(), owner);
    expect(await Promise.race([reached.then(() => true), pending.then(() => false)])).toBe(true);
    const cancellation = native.cancelOriginNotifications(); release();
    expect(await pending).toBe(false); expect(await cancellation).toBe(true);
    expect(api.createTriggerNotification).not.toHaveBeenCalled();
  });

  it("migration restores daily output and stays pending when native permission is denied", async () => {
    const api = schedulerApi(); const { native, storage } = await scheduled(api);
    const reminders = await import("../src/reminders");
    await reminders.setReminderEnabled("owner", true);
    api.requestPermission.mockResolvedValueOnce({ authorizationStatus: 0 });
    await native.migrateOrphanedReminderNotifications("owner");
    expect(await storage.getItem("@mindpattern/reminder.migration.v2.done")).toBeNull();
    expect(api.createTriggerNotification).not.toHaveBeenCalled();
    await native.migrateOrphanedReminderNotifications("owner");
    expect(api.cancelAllNotifications).toHaveBeenCalledTimes(2);
    expect(api.createTriggerNotification).toHaveBeenCalledOnce();
    expect(api.createTriggerNotification.mock.calls[0][0]).toMatchObject({ id: "mindpattern-daily-reminder" });
    expect(await storage.getItem("@mindpattern/reminder.migration.v2.done")).toBe("1");
  });

  it.each(["daily-preference", "measure-preference", "measure-baseline"] as const)("migration remains pending when an empty %s read is superseded", async boundary => {
    const api = schedulerApi(); const { native, ownership, storage } = await scheduled(api);
    const measures = await import("../src/measureReminders");
    if (boundary === "measure-baseline") await measures.setMeasureReminderEnabled("owner", true);
    let entered!: () => void; let release!: () => void;
    const reached = new Promise<void>(resolve => { entered = resolve; });
    const hold = new Promise<void>(resolve => { release = resolve; });
    if (boundary === "measure-baseline") {
      const { secureStore } = await import("../src/secureStore");
      const original = secureStore.getItem.bind(secureStore);
      vi.spyOn(secureStore, "getItem").mockImplementation(async key => {
        const value = await original(key);
        if (key === "@mindpattern/last_measure_owner") { entered(); await hold; }
        return value;
      });
    } else {
      const original = storage.getItem.bind(storage);
      const wanted = boundary === "daily-preference" ? "@mindpattern/reminders_owner" : "@mindpattern/measure_reminders_owner";
      vi.spyOn(storage, "getItem").mockImplementation(async key => {
        const value = await original(key);
        if (key === wanted) { entered(); await hold; }
        return value;
      });
    }
    const pending = native.migrateOrphanedReminderNotifications("owner");
    expect(await Promise.race([reached.then(() => true), pending.then(() => false)])).toBe(true);
    ownership.beginNotificationUpdate("owner", boundary === "daily-preference" ? "daily" : "measure"); release(); await pending;
    expect(api.createTriggerNotification).not.toHaveBeenCalled();
    expect(await storage.getItem("@mindpattern/reminder.migration.v2.done")).toBeNull();
  });

  it("migration fences retirement between the final restoration's settlement and its flag write", async () => {
    const api = schedulerApi(); const { native, lifecycle, storage } = await scheduled(api);
    let release!: (value: string | null) => void; let entered!: () => void;
    const reached = new Promise<void>(resolve => { entered = resolve; });
    const finalRead = new Promise<string | null>(resolve => { release = resolve; });
    const original = storage.getItem.bind(storage);
    vi.spyOn(storage, "getItem").mockImplementation(key => {
      if (key === "@mindpattern/measure_reminders_owner") { entered(); return finalRead; }
      return original(key);
    });
    const pending = native.migrateOrphanedReminderNotifications("owner");
    expect(await Promise.race([reached.then(() => true), pending.then(() => false)])).toBe(true);
    release(null);
    queueMicrotask(() => queueMicrotask(() => { lifecycle.changeLocalSessionOwner("replacement"); }));
    await pending;
    expect(await storage.getItem("@mindpattern/reminder.migration.v2.done")).toBeNull();
  });

  it("migration cannot dispatch a measure reminder after its preference intent changes during permission", async () => {
    const api = schedulerApi(); const { native, ownership, storage } = await scheduled(api);
    const measures = await import("../src/measureReminders");
    await measures.setMeasureReminderEnabled("owner", true);
    await measures.recordMeasureCompleted("owner", "2026-10-05");
    let entered!: () => void; let release!: () => void;
    const reached = new Promise<void>(resolve => { entered = resolve; });
    const hold = new Promise<void>(resolve => { release = resolve; });
    api.requestPermission.mockImplementationOnce(async () => { entered(); await hold; return { authorizationStatus: 1 }; });
    const pending = native.migrateOrphanedReminderNotifications("owner");
    expect(await Promise.race([reached.then(() => true), pending.then(() => false)])).toBe(true);
    ownership.beginNotificationUpdate("owner", "measure"); release(); await pending;
    expect(api.createTriggerNotification).not.toHaveBeenCalled();
    expect(await storage.getItem("@mindpattern/reminder.migration.v2.done")).toBeNull();
  });

  it("unsupplied migration ownership supersedes an older daily producer before restoring preferences", async () => {
    const api = schedulerApi(); const { native, ownership } = await scheduled(api);
    const reminders = await import("../src/reminders");
    await reminders.setReminderEnabled("owner", true);
    let entered!: () => void; let release!: () => void;
    const reached = new Promise<void>(resolve => { entered = resolve; });
    const hold = new Promise<void>(resolve => { release = resolve; });
    api.requestPermission.mockImplementationOnce(async () => { entered(); await hold; return { authorizationStatus: 1 }; });
    const pending = native.scheduleDailyReminder(9, 15, ownership.beginNotificationUpdate("owner", "daily"));
    expect(await Promise.race([reached.then(() => true), pending.then(() => false)])).toBe(true);
    const migration = native.migrateOrphanedReminderNotifications("owner"); release();
    expect(await pending).toBe(false); await migration;
    expect(api.createTriggerNotification).toHaveBeenCalledOnce();
    expect(api.createTriggerNotification.mock.calls[0][0]).toMatchObject({ id: "mindpattern-daily-reminder" });
  });

  it.each(["owned-cancel", "admin-cancel", "origin-cancel", "migration"] as const)("does not dispatch old native work after a session changes during async loading (%s)", async operation => {
    const api = schedulerApi();
    const { native, ownership, lifecycle, storage } = await scheduled(null);
    let release!: (module: unknown) => void; let entered!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const loading = new Promise(resolve => { release = resolve; });
    vi.doMock("@notifee/react-native", async () => { entered(); return await loading; });
    const owner = ownership.beginNotificationUpdate("owner", "daily");
    const pending = operation === "owned-cancel" ? native.cancelDailyReminder("owner", owner)
      : operation === "admin-cancel" ? native.cancelDailyReminder()
      : operation === "origin-cancel" ? native.cancelOriginNotifications()
      : native.migrateOrphanedReminderNotifications("owner", owner);
    expect(await Promise.race([started.then(() => true), pending.then(() => false)])).toBe(true);
    lifecycle.changeLocalSessionOwner("replacement");
    release({ default: api });
    if (operation === "migration") await pending;
    else expect(await pending).toBe(false);
    expect(api.cancelNotification).not.toHaveBeenCalled();
    expect(api.cancelAllNotifications).not.toHaveBeenCalled();
    expect(api.createTriggerNotification).not.toHaveBeenCalled();
    expect(await storage.getItem("@mindpattern/reminder.migration.v2.done")).toBeNull();
  });
});

describe("real notification subscription feeds the navigation queue", () => {
  it.each([undefined, 0, 7])("routes only native PRESS events, including enum %s", async (press) => {
    const events = eventApi(press);
    const { native, route } = await linked(healthApi(), events.module);
    const stop = await native.startNotificationPressRouting();
    expect(stop).toBeTypeOf("function");
    events.fire({ type: (press ?? 1) + 1, detail: { notification: { id: MEASURE_ID } } });
    expect(route.takePendingNotificationRoute()).toBeNull();
    events.fire({ type: press ?? 1, detail: { notification: { id: "unrecognized" } } });
    expect(route.takePendingNotificationRoute()).toBeNull();
    events.fire({ type: press ?? 1, detail: { notification: { id: MEASURE_ID } } });
    expect(route.takePendingNotificationRoute()).toBe("Measures");
    expect(route.takePendingNotificationRoute()).toBeNull();
    stop?.();
    expect(events.unsubscribe).toHaveBeenCalledOnce();
  });

  it("queues a cold-start notification exactly once", async () => {
    const events = eventApi();
    const { native, route } = await linked(healthApi(), events.module);
    const stop = await native.startNotificationPressRouting();
    events.initial({ notification: { id: MEASURE_ID } }); await flush();
    expect(route.takePendingNotificationRoute()).toBe("Measures");
    expect(route.takePendingNotificationRoute()).toBeNull();
    stop?.();
  });

  it.each([null, {}, { notification: {} }, { notification: { id: 1 } }])("ignores an empty or unrecognized initial notification", async (initial) => {
    const events = eventApi();
    const { native, route } = await linked(healthApi(), events.module);
    const stop = await native.startNotificationPressRouting();
    events.initial(initial); await flush();
    expect(route.takePendingNotificationRoute()).toBeNull();
    stop?.();
  });

  it("prevents late cold-start and retained foreground callbacks from routing after disposal", async () => {
    const events = eventApi();
    const { native, route } = await linked(healthApi(), events.module);
    const stop = await native.startNotificationPressRouting();
    expect(stop).toBeTypeOf("function"); stop?.();
    events.initial({ notification: { id: MEASURE_ID } }); await flush();
    events.fire({ type: 1, detail: { notification: { id: MEASURE_ID } } });
    expect(route.takePendingNotificationRoute()).toBeNull();
    expect(events.unsubscribe).toHaveBeenCalledOnce();
  });

  it("keeps a native subscription alive after foreground taps omit optional detail", async () => {
    const events = eventApi();
    const { native, route } = await linked(healthApi(), events.module);
    const stop = await native.startNotificationPressRouting();
    expect(() => events.fire({ type: 1 })).not.toThrow();
    expect(() => events.fire({ type: 1, detail: {} })).not.toThrow();
    expect(route.takePendingNotificationRoute()).toBeNull();
    events.fire({ type: 1, detail: { notification: { id: MEASURE_ID } } });
    expect(route.takePendingNotificationRoute()).toBe("Measures");
    stop?.();
  });

  it.each([null, 3, "linked", { default: 3 }, { default: "linked" }])("declines malformed notification event exports", async (module) => {
    const { native } = await linked(healthApi(), module);
    expect(await native.startNotificationPressRouting()).toBeNull();
  });

  it("checks both event methods before starting native delivery", async () => {
    const getInitialNotification = vi.fn(async () => ({ notification: { id: MEASURE_ID } }));
    const { native, route } = await linked(healthApi(), { default: { getInitialNotification } });
    expect(await native.startNotificationPressRouting()).toBeNull();
    await flush();
    expect(getInitialNotification).not.toHaveBeenCalled();
    expect(route.takePendingNotificationRoute()).toBeNull();
  });

  it.each([false, true])("declines callable event adapters carrying methods (wrapped=%s)", async (wrapped) => {
    const events = eventApi();
    const callable = Object.assign(() => undefined, events.module.default);
    const { native } = await linked(healthApi(), wrapped ? { default: callable } : callable);
    expect(await native.startNotificationPressRouting()).toBeNull();
    expect(events.getInitialNotification).not.toHaveBeenCalled();
    expect(events.onForegroundEvent).not.toHaveBeenCalled();
  });

  it("declines a callable event package even when it carries an object default export", async () => {
    const events = eventApi();
    const { native } = await linked(healthApi(), Object.assign(() => undefined, { default: events.module.default }));
    expect(await native.startNotificationPressRouting()).toBeNull();
    expect(events.getInitialNotification).not.toHaveBeenCalled();
    expect(events.onForegroundEvent).not.toHaveBeenCalled();
  });

  it("leaves no pending route when foreground registration fails", async () => {
    const events = eventApi();
    events.onForegroundEvent.mockImplementationOnce(() => { throw new Error("Cannot subscribe"); });
    const { native, route } = await linked(healthApi(), events.module);
    expect(await native.startNotificationPressRouting()).toBeNull();
    events.initial({ notification: { id: MEASURE_ID } }); await flush();
    expect(route.takePendingNotificationRoute()).toBeNull();
  });
});
