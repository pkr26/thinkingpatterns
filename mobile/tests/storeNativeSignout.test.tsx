import React from "react";
import ReactTestRenderer, { act } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { Text, TouchableOpacity } from "react-native";
import { SessionProvider, useSession } from "../src/store";
import { api } from "../src/api/client";
import { prepareLocalRekey, pendingLocalRekey } from "../src/localRekey";
import { secureStore, setSecureStoreBackend } from "../src/secureStore";
import { __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";
import { vault } from "../src/vault";
import { runTestControl } from "./helpers/testControl";
import storage from "./helpers/storageMock";
import * as keychain from "./helpers/keychainMock";
import * as files from "./helpers/expoFsMock";
import { publicSurface } from "./helpers/publicSurface";
import { assertPublicSurface } from "./helpers/publicSurfaceOracle";

const USER = "c".repeat(32);
let root: ReturnType<typeof ReactTestRenderer.create> | undefined;
function SignoutControl() {
  const session = useSession();
  return <TouchableOpacity accessibilityLabel="Sign out" onPress={session.signOut}><Text>{session.authStatus}</Text></TouchableOpacity>;
}

beforeEach(async () => {
  vi.restoreAllMocks(); storage.__reset(); keychain.__reset(); files.__resetFiles();
  runTestControl(setSecureStoreBackend, null); runTestControl(__resetLocalKeyLifecycleForTests); vault.lock();
  await api.setSession("Native bearer", USER, "native owner");
  vi.stubGlobal("fetch", async (url: string) => {
    const path = new URL(url).pathname;
    const response = new Response(JSON.stringify(path.endsWith("/meta") ? { unlock_days: 30 } : path.endsWith("/insights") ? { active_days: 2 } : {}));
    Object.defineProperty(response, "url", { value: url });
    return response;
  });
});
afterEach(async () => {
  if (root) { await act(async () => root!.unmount()); root = undefined; }
  vi.restoreAllMocks(); vault.lock(); await api.clearSession(); vi.unstubAllGlobals();
});

it("completes Native signout after a sealed rotation checkpoint refuses local cleanup admission", async () => {
  await prepareLocalRekey(USER, Buffer.alloc(32, 7), Buffer.alloc(32, 8), { oldSaltB64: Buffer.alloc(16, 9).toString("base64") });
  await act(async () => { root = ReactTestRenderer.create(<SessionProvider><SignoutControl /></SessionProvider>); });
  await vi.waitFor(() => expect(root!.root.findByType(Text).props.children).toBe("loggedIn"));
  await act(async () => { await root!.root.findByType(TouchableOpacity).props.onPress(); });
  expect(await secureStore.getItem("@mindpattern/token")).toBeNull();
  expect(await secureStore.getItem("@mindpattern/user_id")).toBeNull();
  expect(await secureStore.getItem("@mindpattern/username")).toBeNull();
  expect(root!.root.findByType(Text).props.children).toBe("loggedOut");
  expect(vault.canReauthenticate()).toBe(false);
  expect(await pendingLocalRekey(USER)).toBe(true);
  assertPublicSurface(publicSurface(root), 1);
});
