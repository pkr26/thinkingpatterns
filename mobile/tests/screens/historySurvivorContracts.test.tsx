import React from "react";
import ReactTestRenderer, { act } from "react-test-renderer";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Alert, FlatList, Text, TextInput, TouchableOpacity } from "react-native";
import { HistoryScreen } from "../../src/screens/HistoryScreen";
import { api } from "../../src/api/client";
import { vault } from "../../src/vault";
import { decryptEntry, encryptEntry } from "../../src/crypto/journalCrypto";
import { buildAad, encrypt } from "../../src/crypto/envelope";
import { clearCrisisDialogStamp } from "../../src/crisisDialog";
import { resetEntryVersionMirrors } from "../../src/entryVersions";
import { setSecureStoreBackend } from "../../src/secureStore";
import { __resetLocalKeyLifecycleForTests } from "../../src/localWriteGuard";
import { runTestControl } from "../helpers/testControl";
import storage from "../helpers/storageMock";
import { setFlagsFromString } from "node:v8";
import { runInNewContext } from "node:vm";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const USER = "c".repeat(32);
const KEY = Buffer.alloc(32, 7);
const DAY = "2026-10-05";
let root: ReturnType<typeof ReactTestRenderer.create> | undefined;

function response(url: string, body: unknown, headers: Record<string, string> = {}) {
  const result = new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json", ...headers } });
  Object.defineProperty(result, "url", { value: url });
  return result;
}
function entry(id: string, text: string) {
  return {
    id: `server-${id}`, client_entry_id: id, entry_date: DAY,
    received_at: `${DAY}T12:00:00Z`, content_version: 1,
    blob: encryptEntry({ dataKey: KEY }, USER, id, text, DAY, null, undefined, 1).blobB64,
  };
}
async function flush() {
  await act(async () => { for (let turn = 0; turn < 80; turn++) await Promise.resolve(); });
}
async function mount() {
  await act(async () => { root = ReactTestRenderer.create(<HistoryScreen navigation={{ navigate: vi.fn() }} />); });
  await flush();
}
function text() {
  return root!.root.findAllByType(Text).flatMap(node => node.props.children).flat(Infinity)
    .filter(value => typeof value === "string" || typeof value === "number").join(" ");
}
async function press(label: string) {
  const button = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === label);
  expect(button, `public History action: ${label}`).toBeDefined();
  expect(button!.props.disabled).not.toBe(true);
  await act(async () => { void button!.props.onPress(); });
  await flush();
}
async function chooseAlert(label: string) {
  const choices = vi.mocked(Alert.alert).mock.lastCall?.[2] ?? [];
  const choice = choices.find(button => button.text === label);
  expect(choice, `public History confirmation: ${label}`).toBeDefined();
  await act(async () => { void choice!.onPress?.(); });
  await flush();
}

beforeEach(async () => {
  vi.restoreAllMocks();
  storage.__reset();
  runTestControl(setSecureStoreBackend, null);
  runTestControl(__resetLocalKeyLifecycleForTests);
  runTestControl(resetEntryVersionMirrors);
  vault.lock();
  await api.setSession("history-survivor-bearer", USER, "history-survivor");
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 3), dataKey: Buffer.from(KEY) }, USER);
  await clearCrisisDialogStamp(USER);
});
afterEach(async () => {
  if (root) { await act(async () => root!.unmount()); root = undefined; }
  vault.lock();
  await api.clearSession();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("History public boundary contracts", () => {
  it("editing an authenticated row discards string ratings rather than coercing them into check-ins", async () => {
    const id = "history-string-ratings";
    const row = entry(id, "Earlier plain writing");
    row.blob = encrypt(KEY, Buffer.from(JSON.stringify({
      v: 2, text: "Earlier plain writing", created_at: DAY,
      sentiment: "1", energy: "4", sleep: "3",
    })), buildAad("entry", USER, id, "1")).toString("base64");
    let accepted: ReturnType<typeof decryptEntry> | undefined;
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
      if (init.method === "PUT") {
        const body = JSON.parse(init.body as string);
        accepted = decryptEntry({ dataKey: KEY }, USER, id, body.blob, body.content_version);
        return response(url, {});
      }
      return response(url, [row], { "X-Entries-Revision": "1" });
    });
    await mount();
    await press("Entry from Monday, October 5, 2026");
    await press("Edit this entry");
    await act(async () => root!.root.findAllByType(TextInput)
      .find(node => node.props.accessibilityLabel === "Edit entry")!.props.onChangeText("Updated plain writing"));
    await press("Save changes");
    expect(accepted?.text).toBe("Updated plain writing");
    expect(accepted?.sentiment).toBeNull();
    expect(accepted).not.toHaveProperty("energy");
    expect(accepted).not.toHaveProperty("sleep");
    expect(text()).toContain("Updated plain writing");
  });

  it("a valid first page leaves its next encrypted page physically available", async () => {
    const rows = [entry("history-first-continuation", "First bounded writing")];
    const requested: string[] = [];
    vi.stubGlobal("fetch", async (url: string) => {
      requested.push(url);
      return response(url, rows, { "X-Entries-Revision": "1", "X-Next-Offset": "1" });
    });
    await mount();
    expect(root!.root.findByType(FlatList).props.data).toHaveLength(1);
    expect(requested).toHaveLength(1);
    const download = root!.root.findAllByType(TouchableOpacity)
      .find(node => node.props.accessibilityLabel === "Load older encrypted journal entries");
    expect(download).toBeDefined();
    expect(download!.props.disabled).not.toBe(true);
  });

  it.each(["data key", "vault owner"] as const)("a pending deletion cannot report into a mounted screen after its %s is replaced", async replacement => {
    const row = entry("history-key-replacement", "Writing owned by the earlier key");
    let reached = false;
    let release!: () => void;
    const held = new Promise<void>(resolve => { release = resolve; });
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
      if (init.method === "DELETE") {
        reached = true;
        await held;
        throw new TypeError("The earlier deletion lost its connection");
      }
      return response(url, [row], { "X-Entries-Revision": "1" });
    });
    await mount();
    await press("Entry from Monday, October 5, 2026");
    await press("Delete this entry");
    await chooseAlert("Delete");
    await chooseAlert("Delete permanently");
    expect(reached).toBe(true);
    // The vault takes ownership and zeroizes the previous material itself.
    // A changed account must retire the operation even if the provider
    // reuses the key allocation during that handoff.
    const nextKey = replacement === "vault owner" ? vault.get().dataKey : Buffer.alloc(32, 19);
    await act(async () => vault.unlock({
      masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 4), dataKey: nextKey,
    }, replacement === "vault owner" ? "d".repeat(32) : USER));
    vi.mocked(Alert.alert).mockClear();
    release();
    await flush();
    expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
  });

  it("an overlapping calendar download preserves the authenticated rows already shown", async () => {
    const row = entry("history-replayed-wire-row", "Authenticated downloaded writing");
    const requests: string[] = [];
    vi.stubGlobal("fetch", async (url: string) => {
      requests.push(url);
      const rows = new URL(url).searchParams.has("since") ? [row] : [row, row];
      return response(url, rows, { "X-Entries-Revision": "1" });
    });
    await mount();
    expect(root!.root.findByType(FlatList).props.data).toHaveLength(2);
    await press("Previous month");
    expect(requests.some(url => new URL(url).searchParams.has("since"))).toBe(true);
    expect(root!.root.findByType(FlatList).props.data).toHaveLength(2);
  });

  it("closing History releases its decrypted writing while a transient confirmation was visible", async () => {
    const row = entry("history-status-retirement", "Private writing must retire with the screen");
    vi.stubGlobal("fetch", async (url: string) => response(url,
      new URL(url).searchParams.has("since") ? [] : [row], { "X-Entries-Revision": "1" }));
    await mount();
    await press("Previous month");
    expect(text()).toContain("No entries");
    const retiredWriting = new WeakRef(root!.root.findByType(FlatList).props.data[0] as object);
    await act(async () => { root!.unmount(); root = undefined; });
    setFlagsFromString("--expose_gc");
    const collect = runInNewContext("gc") as () => void;
    for (let attempt = 0; attempt < 8; attempt++) {
      await new Promise<void>(resolve => setImmediate(resolve)); collect();
    }
    expect(retiredWriting.deref(), "a visible status must not retain a closed journal screen").toBeUndefined();
  });

  it.each(["older page", "deletion"] as const)(
    "a completed %s releases its controls after a same-account credential refresh", async operation => {
      const row = entry("history-credential-refresh", "Writing still owned by the same account");
      let reached = false, first = true;
      let release!: () => void;
      const held = new Promise<void>(resolve => { release = resolve; });
      let accepted: ReturnType<typeof decryptEntry> | undefined;
      vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
        const older = new URL(url).searchParams.get("offset") === "1";
        if (first && ((operation === "older page" && older) || (operation === "deletion" && init.method === "DELETE"))) {
          first = false; reached = true; await held;
          throw new TypeError("The earlier request ended after credentials refreshed");
        }
        if (older || init.method === "PUT") {
          expect(new Headers(init.headers).get("Authorization")).toBe("Bearer history-fresh-credential-bearer");
          if (init.method === "PUT") {
            const body = JSON.parse(init.body as string);
            accepted = decryptEntry({ dataKey: KEY }, USER, row.client_entry_id, body.blob, body.content_version);
            return response(url, {});
          }
          return response(url, [entry("history-current-older-page", "Current authenticated older writing")], { "X-Entries-Revision": "1" });
        }
        return response(url, [row], { "X-Entries-Revision": "1", "X-Next-Offset": "1" });
      });
      try {
        await mount();
        if (operation === "older page") await press("Load older encrypted journal entries");
        else {
          await press("Entry from Monday, October 5, 2026"); await press("Delete this entry");
          await chooseAlert("Delete"); await chooseAlert("Delete permanently");
        }
        expect(reached).toBe(true);
        await api.setSession("history-fresh-credential-bearer", USER, "history-survivor");
        release(); await flush();
        if (operation === "older page") {
          await press("Load older encrypted journal entries");
          expect(root!.root.findByType(FlatList).props.data).toHaveLength(2);
        } else {
          await press("Edit this entry");
          await act(async () => root!.root.findAllByType(TextInput)
            .find(node => node.props.accessibilityLabel === "Edit entry")!.props.onChangeText("Writing saved with current credentials"));
          await press("Save changes");
          expect(accepted?.text).toBe("Writing saved with current credentials");
        }
      } finally { release(); await flush(); }
    },
  );

});
