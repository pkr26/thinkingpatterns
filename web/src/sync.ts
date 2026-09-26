/**
 * The multi-device reconciliation engine (WEB_PLAN P5, contract S-1):
 * the server is the single source of truth; this module pulls fresh truth
 * at the honest moments — login, regained focus, regained connectivity —
 * under a Web Lock so two tabs never reconcile concurrently, and routes
 * the account-wide death funnels (D-8) to the app with the right reason.
 *
 * What reconciliation does NOT do: merge. Entries pages walk under one
 * revision snapshot or restart (S-5); insights decrypt through the
 * state_seq guard (S-6); a decrypt failure with a live session means the
 * data key changed elsewhere (S-8) and surfaces as `credentialRotated` —
 * never a retry loop, never stale keys.
 */
import { ApiError, api, hasSession, listEntriesWalk, sessionUserId } from "./api/client";
import { decryptInsights, type InsightsPayload } from "./crypto/patient";
import { checkAnalysisGeneration, FRESHNESS_ERROR } from "./stateSeqGuard";
import { withLock } from "./platform";
import { vault } from "./vault";

export type ReconcileOutcome =
  | { kind: "ok"; phase: string; stateSeq: number | null }
  | { kind: "offline" }
  | { kind: "locked" }
  | { kind: "credentialRotated" }
  | { kind: "freshness" }
  | { kind: "error"; message: string };

/** Pull the account's analysis state and verify its generation. Called at
 *  the honest moments; every insight render routes through here so the
 *  state_seq guard is not a screen-by-screen convention. */
export async function reconcileInsights(): Promise<ReconcileOutcome> {
  if (!hasSession()) return { kind: "locked" };
  const owner = sessionUserId();
  // isUnlocked BEFORE get(): the getter throws on a locked vault, and this
  // path must report "locked", not crash.
  if (!owner || !vault.isUnlocked() || vault.ownerUserId() !== owner) return { kind: "locked" };
  const keys = vault.get();
  let summary;
  try {
    summary = await api.insights();
  } catch (err) {
    if (err instanceof ApiError && err.status === 0) return { kind: "offline" };
    // 401/410 funnels fire the client's session-expiry latch (App handles
    // the lockdown); here they only end this reconciliation.
    if (err instanceof ApiError && (err.status === 401 || err.status === 410)) return { kind: "locked" };
    return { kind: "error", message: err instanceof Error ? err.message : "reconciliation failed" };
  }
  if (summary.blob === null) {
    // Baseline phase: nothing is decrypted before the threshold — there is
    // no generation to guard yet.
    return { kind: "ok", phase: summary.phase, stateSeq: null };
  }
  let payload: InsightsPayload;
  try {
    payload = await decryptInsights(keys.dataKey, owner, summary.blob);
  } catch {
    // The session is alive but the data key cannot open the blob: the
    // password was rotated on ANOTHER device and the corpus was rekeyed
    // (S-8). Fail closed with the actionable funnel — never loop.
    return { kind: "credentialRotated" };
  }
  try {
    await checkAnalysisGeneration(owner, payload.state_seq, summary.state_seq);
  } catch (err) {
    if (err instanceof Error && err.message === FRESHNESS_ERROR) return { kind: "freshness" };
    throw err;
  }
  return { kind: "ok", phase: summary.phase, stateSeq: payload.state_seq ?? null };
}

/** The full honest-moment pull (S-1): insights + one reconciliation pass
 *  of the entries walk, serialized across tabs. Screens subscribe to the
 *  outcome; nothing here merges. */
export async function reconcile(): Promise<ReconcileOutcome> {
  return withLock("mindpattern-reconcile", async () => {
    const outcome = await reconcileInsights();
    // A fresh entries pass only matters when the analysis state read
    // succeeded (or is baseline) — the error funnels take priority.
    if (outcome.kind === "ok") {
      try {
        await listEntriesWalk();
      } catch (err) {
        if (err instanceof ApiError && err.status === 0) return { kind: "offline" } as ReconcileOutcome;
        if (err instanceof ApiError && (err.status === 401 || err.status === 410)) return { kind: "locked" } as ReconcileOutcome;
        // collection_changed storms already restart inside the walk; any
        // other failure is surfaced but does not undo the insights result.
        return { kind: "error", message: err instanceof Error ? err.message : "entries reconciliation failed" } as ReconcileOutcome;
      }
    }
    return outcome;
  });
}
