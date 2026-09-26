/** App-level legacy mute adoption (2026-09-26 audit follow-up, B-6): the
 *  pre-fix plaintext mute list must move into the encrypted kv blob at
 *  SIGN-IN — without the user ever visiting Patterns. Mirrors app.test's
 *  mocked-LoginView harness (deterministic, no PBKDF2 waits) but runs on
 *  REAL timers so the adoption's real AES-GCM round-trip can settle. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { vault } from "../src/vault";
import { decrypt, fromBase64 } from "../src/crypto/core";
import { buildAad } from "../src/crypto/aad";
import { setKvBackendForTests, type KvBackend } from "../src/kvstore";
import { jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { press, render, settle, textOf } from "./helpers/rtr";

const USER = "user-7";
/** Must match the bytes the mocked LoginView unlocks with (vi.mock
 *  factories are hoisted above module consts, so the factory inlines its
 *  own copy — 32 bytes of 0x05 — and this mirror decrypts the blob). */
const DATA_KEY = new Uint8Array(new ArrayBuffer(32)).fill(5);
const LEGACY_KEY = `mindpattern.mutedPids.v1.${USER}`;
const BLOB_KEY = `mindpattern.patternMutes.v1.${USER}`;

vi.mock("../src/views/LoginView", async () => {
  const { setSession } = await import("../src/api/client");
  const { vault } = await import("../src/vault");
  const React = await import("react");
  return {
    LoginView: (props: { onSuccess: (s: { userId: string; username: string }) => void }) =>
      React.createElement("button", {
        onClick: () => {
          setSession("tok", "user-7", "alice");
          vault.unlock({ authKey: new Uint8Array(new ArrayBuffer(32)), dataKey: new Uint8Array(new ArrayBuffer(32)).fill(5) }, "user-7");
          props.onSuccess({ userId: "user-7", username: "alice" });
        },
      }, "Sign in"),
  };
});

const winStorage = (): Storage | undefined => (globalThis as { window?: { localStorage?: Storage } }).window?.localStorage;

describe("App adopts the legacy plaintext mute list at sign-in (2026-09-26 audit follow-up, B-6)", () => {
  let kvMap: Map<string, string>;

  beforeEach(() => {
    resetTestState();
    kvMap = new Map<string, string>();
    const backend: KvBackend = {
      async getItem(k) {
        return kvMap.get(k) ?? null;
      },
      async setItem(k, v) {
        kvMap.set(k, v);
      },
      async removeItem(k) {
        kvMap.delete(k);
      },
      async keys() {
        return [...kvMap.keys()];
      },
    };
    setKvBackendForTests(backend);
    winStorage()?.clear();
    stubFetch(() => jsonResponse({ detail: "unmatched" }, { status: 404 }));
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    setKvBackendForTests(null);
  });

  it("moves legacy pids into the encrypted kv blob without visiting Patterns", async () => {
    winStorage()?.setItem(LEGACY_KEY, JSON.stringify(["topic:legacy"]));
    const root = await render(<App />);
    await settle(60, 2); // boot beat → login
    expect(textOf(root)).toContain("Sign in");
    await press(root, "Sign in");
    await settle(60, 4); // the adoption's real AES-GCM round-trip
    // The session unlocked for the right account...
    expect(vault.ownerUserId()).toBe(USER);
    // ...and the flow never left onboarding: Patterns was NOT mounted, so
    // the adoption below can only have come from the sign-in path.
    expect(textOf(root)).toContain("A journal that is yours alone");
    // The legacy plaintext copy is gone...
    expect(winStorage()?.getItem(LEGACY_KEY)).toBeNull();
    // ...and the pid lives ONLY as ciphertext, decryptable under the data key.
    const stored = kvMap.get(BLOB_KEY);
    expect(stored).toBeTruthy();
    expect(stored!).not.toContain("legacy");
    const opened = await decrypt(DATA_KEY, fromBase64(stored!), buildAad("pattern-mutes", USER));
    expect(JSON.parse(new TextDecoder().decode(opened))).toEqual(["topic:legacy"]);
  });

  it("is a no-op when no legacy list exists (fresh accounts start clean)", async () => {
    const root = await render(<App />);
    await settle(60, 2);
    await press(root, "Sign in");
    await settle(60, 4);
    expect(winStorage()?.getItem(LEGACY_KEY)).toBeNull();
    expect(kvMap.has(BLOB_KEY)).toBe(false);
  });
});
