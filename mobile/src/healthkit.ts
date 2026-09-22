/**
 * HealthKit State of Mind seam (2026-09-19).
 *
 * The native module this seam drives is react-native-health — but the
 * community package (1.19.0, the newest published) predates iOS 18 and
 * carries NO State of Mind path natively, so
 * ios/MindPattern/HealthBridge/RCTAppleHealthKit+MindPatternStateOfMind.m
 * (2026-09-22, independent-audit NEW-2) attaches a category onto the
 * pod's module implementing exactly the contract below; the package's JS
 * wrapper spreads the native module's methods, so the seam lights up the
 * moment the app target compiles that file. Capability probing still
 * degrades to "unavailable" — never a crash — when the bridge is absent,
 * the device predates iOS 18, or a write fails; every write path returns
 * false rather than throwing (the notifee/biometrics pattern).
 *
 * NATIVE-MODULE CONTRACT — what the bridge must expose when it links:
 *  - Module name: "react-native-health" (the ecosystem standard package).
 *  - requestAuthorization(scopes): asks for WRITE access to the
 *    HKStateOfMindCategoryType. The scope object this seam passes is
 *    always { stateOfMind: { write: true } } — read is deliberately never
 *    requested. NOTE for the bridge implementer: HealthKit's
 *    requestAuthorization resolves even when the user denies, so the
 *    bridge must consult the authorization status itself before answering
 *    true.
 *  - getAuthorizationStatus(scopes): reports the current status for the
 *    same category, shaped { stateOfMind: number } with HealthKit's own
 *    HKAuthorizationStatus values (0 notDetermined, 1 sharingDenied,
 *    2 sharingAuthorized). The seam treats only an explicit sharingDenied
 *    (1) as refusal — everything else fails toward attempting the write,
 *    which can only fail honestly.
 *  - saveStateOfMind(sample): persists one record
 *    { kind, valence, date } where kind is one of the five labels below,
 *    valence is HealthKit's DISCRETE -2..2 classification, and date is an
 *    ISO-8601 local calendar day.
 *  - A linked module that lacks saveStateOfMind (pre-iOS-18 State of Mind
 *    support) reads as unavailable with its own reason, not as broken.
 *
 * PRIVACY POSTURE — v1 scope is WRITE-ONLY: MindPattern mirrors the
 * user's own explicit mood check-in OUT to the Health app on this device;
 * it never reads anything from Health. No read permission is requested,
 * no Health data crosses into MindPattern, and the Settings copy says so.
 * Turning the preference off stops future writes; what the Health app
 * already holds stays in Health (MindPattern cannot and will not delete
 * from it).
 *
 * The preference record (mirrorMoodToHealth, default OFF) follows the
 * reminders.ts idiom: a plain AsyncStorage per-account record — a
 * non-sensitive preference, never journal content — validated in full on
 * read, failing toward the disabled default. Account deletion must wipe
 * it (clearMoodMirrorPref rides the SettingsScreen deletion flow).
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { Platform } from "react-native";
import type { NativeCapability } from "./nativeFeatures";

/** The module this seam probes for — the ecosystem-standard HealthKit
 *  package name, kept in one place so the contract above stays greppable. */
const HEALTH_MODULE = "react-native-health";

function probe(moduleName: string): unknown | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const mod = require(moduleName);
    return mod ?? null;
  } catch {
    return null;
  }
}

/** Async resolution for the ACTION seams: the synchronous require first
 *  (the RN bundler path — a linked module resolves statically), then a
 *  dynamic import so test builds can inject the module through the module
 *  runner (vi.mock intercepts `import()`, not `require()`). Both failures
 *  read as "absent" — never a throw. (Same idiom as nativeFeatures.ts.) */
async function probeAsync(moduleName: string): Promise<unknown | null> {
  const mod = probe(moduleName);
  if (mod !== null) return mod;
  try {
    return await import(moduleName);
  } catch {
    return null;
  }
}

/** The five HKStateOfMind valence classifications, most unpleasant first.
 *  HealthKit's valence is a DISCRETE -2..2 classification; MindPattern's
 *  check-in scale is CONTINUOUS [-1, 1] (src/mood.ts), so the mirror
 *  quantizes before writing. */
export type StateOfMindKind =
  | "very_unpleasant"
  | "unpleasant"
  | "neutral"
  | "pleasant"
  | "very_pleasant";

const KINDS: readonly StateOfMindKind[] = [
  "very_unpleasant",
  "unpleasant",
  "neutral",
  "pleasant",
  "very_pleasant",
];

/**
 * PURE: quantize a continuous [-1, 1] valence onto HealthKit's five
 * discrete levels. The five check-in picks (-1, -0.5, 0, 0.5, 1) land on
 * the five levels one-to-one; a value between picks rounds to the nearer
 * label (exact halves round toward pleasant). Out-of-range values clamp
 * to the ends — a hostile caller must not manufacture a sixth level. A
 * non-finite value is not a mood at all and returns null, which the
 * write path treats as "do not write".
 */
export function stateOfMindKind(valence: number): StateOfMindKind | null {
  if (!Number.isFinite(valence)) return null;
  const clamped = Math.min(1, Math.max(-1, valence));
  const level = Math.round(clamped * 2); // -2..2
  return KINDS[level + 2] ?? null;
}

/** The react-native-health surface this seam touches (the CONTRACT in the
 *  module header; the real package exports far more). */
interface HealthModule {
  requestAuthorization(scopes: unknown): Promise<boolean | void> | boolean | void;
  getAuthorizationStatus?(scopes: unknown): Promise<unknown> | unknown;
  saveStateOfMind(sample: { kind: StateOfMindKind; valence: number; date: string }): Promise<boolean | void> | boolean | void;
}

/** The ONLY scope object this seam ever passes: State of Mind, WRITE. The
 *  read half of the category is never requested — write-only is the
 *  privacy posture, and keeping it a single frozen constant means a
 *  future edit cannot quietly widen it. */
const WRITE_SCOPES = Object.freeze({ stateOfMind: { write: true } });

/** HKAuthorizationStatus.sharingDenied — HealthKit's own enum value (0
 *  notDetermined / 1 sharingDenied / 2 sharingAuthorized); the only
 *  status this seam reads a refusal from. */
const HK_AUTH_STATUS_SHARING_DENIED = 1;

function healthFrom(mod: unknown): HealthModule | null {
  if (mod === null || typeof mod !== "object") return null;
  // The package's default export carries the API; tolerate a bare object.
  const candidate = (mod as { default?: unknown }).default ?? mod;
  if (typeof candidate !== "object" || candidate === null) return null;
  const api = candidate as Partial<HealthModule>;
  if (typeof api.requestAuthorization !== "function") return null;
  if (typeof api.saveStateOfMind !== "function") return null;
  return api as HealthModule;
}

/** Synchronous capability probe for Settings. The reasons are ordered
 *  most-fundamental first: "not linked" (this build), "requires iOS 18"
 *  (the device — State of Mind shipped with iOS 18, and the local
 *  HealthBridge category answers unavailable there by design), and
 *  "predates State of Mind support" (a react-native-health build without
 *  the bridge category) are three different facts for the person reading
 *  the reason line. */
export function healthKitCapability(): NativeCapability {
  const mod = probe(HEALTH_MODULE);
  if (mod === null) {
    return { available: false, reason: "health module not linked in this build" };
  }
  if (Platform.OS === "ios") {
    const version = typeof Platform.Version === "number" ? Platform.Version : Number.parseFloat(String(Platform.Version));
    if (Number.isFinite(version) && version < 18) {
      return { available: false, reason: "Apple Health State of Mind requires iOS 18 or later" };
    }
  }
  if (healthFrom(mod) === null) {
    return { available: false, reason: "health module predates State of Mind support" };
  }
  return { available: true };
}

/** Ask (or re-ask) for WRITE access to the State of Mind category and
 *  report whether it landed. HealthKit quirk this exists for: the request
 *  call itself does not fail on denial, so the status is consulted
 *  afterwards; only an explicit sharingDenied reads as refused. Returns
 *  false — never throws — when the module is absent or the call fails. */
async function writeAccessGranted(api: HealthModule): Promise<boolean> {
  const granted = await api.requestAuthorization(WRITE_SCOPES);
  if (granted === false) return false;
  if (typeof api.getAuthorizationStatus === "function") {
    const status = await api.getAuthorizationStatus(WRITE_SCOPES);
    const state =
      typeof status === "object" && status !== null
        ? (status as { stateOfMind?: unknown }).stateOfMind
        : undefined;
    if (state === HK_AUTH_STATUS_SHARING_DENIED) return false;
  }
  return true;
}

/** Settings' toggle-on path: request write access NOW, so the OS prompt
 *  happens where the user just flipped the switch (not at the next
 *  check-in), and a denial is reported honestly instead of surfacing as
 *  silently-missing Health entries. False — never a throw — when the
 *  module is absent, access is denied, or the call fails. */
export async function ensureStateOfMindWriteAccess(): Promise<boolean> {
  const api = healthFrom(await probeAsync(HEALTH_MODULE));
  if (api === null) return false;
  try {
    return await writeAccessGranted(api);
  } catch {
    return false;
  }
}

/**
 * Write one mood check-in to the Health app as an HKStateOfMind sample.
 * The continuous [-1, 1] valence is quantized to HealthKit's discrete
 * classification (stateOfMindKind) before anything crosses the bridge.
 * Returns false — never throws — when the module is absent (this build),
 * the valence is not a finite number, write access is denied, or the
 * native call fails. The caller (the entry save path) treats false as
 * "nothing was mirrored this time" and never alarms the user.
 */
export async function writeStateOfMind(valence: number, dateISO: string): Promise<boolean> {
  const kind = stateOfMindKind(valence);
  if (kind === null) return false;
  const api = healthFrom(await probeAsync(HEALTH_MODULE));
  if (api === null) return false;
  try {
    if (!(await writeAccessGranted(api))) return false;
    const saved = await api.saveStateOfMind({
      kind,
      valence: KINDS.indexOf(kind) - 2,
      date: dateISO,
    });
    return saved !== false;
  } catch {
    return false;
  }
}

// --------------------------------------------------------------------------
// The per-account mirror preference (the reminders.ts idiom).
// --------------------------------------------------------------------------

interface MirrorPrefs {
  enabled: boolean;
}

/** OFF until the user opts in — the app never writes to Health unasked. */
const DEFAULT_MIRROR_PREFS: Readonly<MirrorPrefs> = { enabled: false };

const key = (userId: string): string => `@mindpattern/mirror_mood_to_health_${userId}`;

/** Full validation of anything read back from storage. null = not a
 *  usable record (absent, unparsable, or hostile). */
function parsePrefs(raw: string | null): MirrorPrefs | null {
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return null;
    const { enabled } = parsed as Record<string, unknown>;
    if (typeof enabled !== "boolean") return null;
    return { enabled };
  } catch {
    return null;
  }
}

/** The stored preference, or the disabled default when absent/corrupt
 *  (failure direction is toward OFF: a phantom "enabled" would write to
 *  Health behind the user's back, which is the worse failure). Never
 *  throws — Settings and the entry save path both read this casually. */
export async function getMoodMirrorPref(userId: string): Promise<boolean> {
  try {
    return (parsePrefs(await AsyncStorage.getItem(key(userId))) ?? DEFAULT_MIRROR_PREFS).enabled;
  } catch {
    return DEFAULT_MIRROR_PREFS.enabled;
  }
}

async function writePrefs(userId: string, prefs: MirrorPrefs): Promise<void> {
  await AsyncStorage.setItem(key(userId), JSON.stringify(prefs));
}

/** Flip the opt-in. Throwing surfaces to the caller as an honest failure —
 *  the UI never pretends a preference was saved when it was not. */
export async function setMoodMirrorPref(userId: string, enabled: boolean): Promise<void> {
  await writePrefs(userId, { enabled });
}

/** Account-deletion hygiene: the preference must not outlive its account. */
export async function clearMoodMirrorPref(userId: string): Promise<void> {
  await AsyncStorage.removeItem(key(userId));
}

/**
 * Fire-and-forget helper for the entry save path: mirror ONE successful
 * mood check-in when (and only when) the per-account preference is on.
 * Returns false — never throws — on every skip and every failure, so the
 * entry save can invoke it without awaiting and swallow the result. The
 * vault-locked guard is the caller's (EntryScreen holds the vault), not
 * this module's: healthkit.ts deliberately knows nothing about app state.
 */
export async function mirrorMoodCheckIn(userId: string, valence: number, dateISO: string): Promise<boolean> {
  if (!(await getMoodMirrorPref(userId))) return false;
  return writeStateOfMind(valence, dateISO);
}
