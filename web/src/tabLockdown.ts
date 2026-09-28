/**
 * Cross-tab session lockdown (audit 2026-09-28, M-4).
 *
 * A v1 password rotation rekeys the SERVER corpus but could not see
 * another signed-in tab: that tab still held the OLD data key and a valid
 * bearer, and its direct online save (or its own reconnect flush)
 * uploaded old-key-sealed blobs to an already-rekeyed corpus — rows the
 * server has no possession check to refuse, permanently undecryptable.
 * The rotation therefore BROADCASTS a lockdown before its first server
 * step, and every live tab of this origin funnels the message into the
 * same lockDown the idle/hidden-tab locks use (clearSession + vault.lock
 * + queue fence — the ciphertext itself stays parked, D-9).
 *
 * BroadcastChannel when the browser has it. Browsers without it (the same
 * old-Safari population as the Web Locks fallback) keep the per-tab
 * drain protection only — disclosed here rather than silently claimed.
 */
const CHANNEL_NAME = "mindpattern-session-lockdown";

export type TabLockdownReason = "rotation";

interface LikeChannel {
  postMessage(message: unknown): void;
  close(): void;
  onmessage: ((event: { data: unknown }) => void) | null;
}

type ChannelCtor = new (name: string) => LikeChannel;

function channelCtor(): ChannelCtor | null {
  const candidate = (globalThis as { BroadcastChannel?: unknown }).BroadcastChannel;
  return typeof candidate === "function" ? (candidate as ChannelCtor) : null;
}

/** Tell every OTHER live tab of this origin to lock down NOW. Fire and
 *  forget: a tab that misses the message keeps the drain's protection. */
export function broadcastTabLockdown(reason: TabLockdownReason): void {
  const Ctor = channelCtor();
  if (Ctor === null) return;
  try {
    const channel = new Ctor(CHANNEL_NAME);
    channel.postMessage({ reason });
    channel.close();
  } catch {
    // Broadcasting must never break the caller's own rotation.
  }
}

/** Subscribe this tab to other tabs' lockdown broadcasts; returns the
 *  unsubscribe (the App's effect cleanup). */
export function subscribeTabLockdown(handler: (reason: TabLockdownReason) => void): () => void {
  const Ctor = channelCtor();
  if (Ctor === null) return () => undefined;
  const channel = new Ctor(CHANNEL_NAME);
  channel.onmessage = (event) => {
    const reason = (event.data as { reason?: unknown } | null)?.reason;
    if (reason === "rotation") handler("rotation");
  };
  return () => {
    channel.onmessage = null;
    channel.close();
  };
}
