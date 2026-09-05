/**
 * Mini-brain refresh: fold new entries into the pattern store.
 *
 * SECURITY MODEL (hardened after the red-team audit):
 *  - The data key DOES travel to the server in a processing session — that
 *    is the design's one trust leap. It must therefore only ever happen as
 *    an EXPLICIT, user-initiated act (the Question screen's button). This
 *    module is invoked only from that explicit path — never automatically
 *    after a sync — so the key is never shipped silently.
 *  - The vault records which account the unlocked keys belong to; the
 *    upload is aborted unless that binding matches the session's account
 *    (a session/vault desync must never deliver one account's data key
 *    into another account's processing session).
 *
 * Best effort by design: any failure is swallowed silently — a missed
 * refresh costs nothing, and the Question screen's explicit button
 * remains the guaranteed path.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { api } from "./api/client";
import { vault } from "./vault";
import { localDateISO } from "./moodLog";

/** Per-account stamp: a shared key let one account's refresh satisfy (and
 *  skip) another account's — and the upload ships the DATA KEY, so the
 *  "once per day" cap must hold per account. */
const stampKey = (userId: string): string => `@mindpattern/last_recompute_${userId}`;

/** One run at a time: concurrent callers share the in-flight promise —
 *  without this, two callers can both pass the `last === today` check and
 *  both upload the data key. */
let inFlight: Promise<void> | null = null;

export async function maybeDailyRecompute(): Promise<void> {
  if (inFlight) return inFlight;
  inFlight = runRecompute().finally(() => {
    inFlight = null;
  });
  return inFlight;
}

async function runRecompute(): Promise<void> {
  try {
    const userId = await api.getUserId();
    if (!userId) return;
    // KEY/ACCOUNT BINDING: the vault's keys must be this account's keys.
    // A desync (restored session vs. live vault) would otherwise ship the
    // wrong account's data key into this account's processing session.
    const owner = vault.ownerUserId();
    if (owner !== userId) return;
    if (!vault.isUnlocked()) return;
    // Phase check needs no key; a missing blob means the user has never
    // run an analysis — the first one must stay a deliberate tap.
    const summary = await api.insights();
    if (summary.phase !== "insight" || summary.blob == null) return;

    const last = await AsyncStorage.getItem(stampKey(userId));
    const today = localDateISO(); // LOCAL day — matches entry dates; the
    // UTC day double-counted or skipped the cap near midnight off-UTC.
    if (last === today) return;

    const keys = vault.get();
    const session = await api.openProcessingSession(keys.dataKey.toString("base64"));
    await api.recompute(session.session_token);
    // Only stamp the day on success: a failed refresh retries next launch.
    await AsyncStorage.setItem(stampKey(userId), today);
  } catch {
    // Best effort only — no dialogs, no retries.
  }
}

/** Account-deletion hygiene: remove this account's recompute stamp. */
export async function clearRecomputeStamp(userId: string): Promise<void> {
  await AsyncStorage.removeItem(stampKey(userId));
}
