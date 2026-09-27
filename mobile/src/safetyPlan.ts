/**
 * The local safety plan (2026-09-27) — minimal, honest, Stanley-Brown-
 * inspired structure. Six fields the user fills about their own hard
 * times: warning signs, coping strategies, people & places, who they can
 * ask for help, professionals/services, and making their environment
 * safer. The structure borrows from the widely used safety-planning
 * approach (Stanley & Brown); the app adds nothing clinical to it — no
 * scoring, no interpretation, no advice. It is a personal tool the user
 * writes for themselves, one tap from crisis help.
 *
 * PRIVACY (the whole point of doing this at all): the plan is encrypted
 * under the account's DATA KEY — AES-256-GCM with AAD binding the user —
 * exactly like the mood log and pending measures (the vault/kvstore
 * idiom). It never leaves the device, the server stores nothing, and a
 * filesystem reader gets ciphertext. Per-user slot:
 * @mindpattern/safety_plan_<userId>. A wrong key (account switch,
 * rotation) or tampered blob reads as ABSENT, never as a partial plan.
 *
 * POSITION IN THE SAFETY SURFACE: a SUPPLEMENT, never a gate. The static
 * crisis resources (numbers, chat, 911) stay first, always available,
 * offline and pre-unlock; the plan is one more thing a person can hold,
 * readable only while the vault is unlocked.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { buildAad, decrypt, encrypt } from "./crypto/envelope";

/** The six Stanley-Brown-inspired fields, in the screen's display order. */
export interface SafetyPlan {
  /** Personal warning signs a hard time is starting. */
  warningSigns: string;
  /** Internal strategies — things that have calmed or grounded the user. */
  copingStrategies: string;
  /** People and places that provide distraction. */
  peoplePlaces: string;
  /** People to ask for help (name + number, the user's own words). */
  askForHelp: string;
  /** Professionals and agencies (therapist, doctor, crisis lines). */
  professionals: string;
  /** Making the environment safer. */
  environmentSafer: string;
}

export const SAFETY_PLAN_FIELDS: readonly (keyof SafetyPlan)[] = [
  "warningSigns",
  "copingStrategies",
  "peoplePlaces",
  "askForHelp",
  "professionals",
  "environmentSafer",
];

/** Generous but bounded: a plan field is a note, not a document — the
 *  bound keeps a hostile/half-written blob from masquerading as megabytes
 *  of "plan" in memory. */
const MAX_FIELD_CHARS = 4_000;

export function emptySafetyPlan(): SafetyPlan {
  return {
    warningSigns: "",
    copingStrategies: "",
    peoplePlaces: "",
    askForHelp: "",
    professionals: "",
    environmentSafer: "",
  };
}

const key = (userId: string): string => `@mindpattern/safety_plan_${userId}`;

/** Full validation of anything read back from storage (the pendingMeasure
 *  discipline): every field must be a bounded string; anything else is a
 *  hostile or half-written record and reads as absent. */
function parsePlan(raw: string | null): SafetyPlan | null {
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return null;
    const plan = emptySafetyPlan();
    for (const field of SAFETY_PLAN_FIELDS) {
      const value = (parsed as Record<string, unknown>)[field];
      if (typeof value !== "string" || value.length > MAX_FIELD_CHARS) return null;
      plan[field] = value;
    }
    return plan;
  } catch {
    return null;
  }
}

/** Persist the plan under the data key. The key is snapshotted at call
 *  time (the moodLog/pendingMeasure idiom): the vault may lock between
 *  this call and the serialized write, and encrypting under a zeroized
 *  buffer must never produce a blob no future read can open. Throws on a
 *  storage failure — the screen reports it honestly; the plan is also
 *  still on screen. */
export async function saveSafetyPlan(dataKey: Buffer, userId: string, plan: SafetyPlan): Promise<void> {
  const keyCopy = Buffer.from(dataKey);
  const blob = encrypt(
    keyCopy,
    Buffer.from(JSON.stringify(plan), "utf8"),
    buildAad("safety-plan", userId),
  );
  await AsyncStorage.setItem(key(userId), blob.toString("base64"));
}

/** The plan for this account, or null when absent, corrupt, or under the
 *  wrong key (account switch / rotation). Never throws — a plan that
 *  cannot be read is reported as absent; the user can always write a new
 *  one, and the static crisis resources never depended on it. */
export async function loadSafetyPlan(dataKey: Buffer, userId: string): Promise<SafetyPlan | null> {
  try {
    const keyCopy = Buffer.from(dataKey);
    const raw = await AsyncStorage.getItem(key(userId));
    if (!raw) return null;
    const plain = decrypt(keyCopy, Buffer.from(raw, "base64"), buildAad("safety-plan", userId));
    return parsePlan(plain.toString("utf8"));
  } catch {
    return null;
  }
}

/** Account-deletion hygiene (the deletion flow locks the vault first, so
 *  this intentionally needs NO key — it removes the slot, it does not
 *  read it). The plan must not outlive its account on a shared device. */
export async function clearSafetyPlan(userId: string): Promise<void> {
  await AsyncStorage.removeItem(key(userId));
}
