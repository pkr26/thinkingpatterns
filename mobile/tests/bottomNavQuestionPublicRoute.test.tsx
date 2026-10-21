/** Public Login, shipped navigator declarations/screens and visible Question
 * transition. The accepted one-visible-route host substitutes Native stack
 * presentation only; no screen controller or navigation result is mocked. */
import React from "react";
import { hkdfSync, pbkdf2Sync } from "node:crypto";
import TestRenderer, { act } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { Text, TextInput, TouchableOpacity } from "react-native";

vi.mock("@react-navigation/native-stack", async () => {
  const React = await import("react");
  const { Text } = await import("react-native");
  type Route = { name: string; component: React.ComponentType<{ navigation: unknown }>; options?: { headerShown?: boolean; title?: string } };
  function collect(children: React.ReactNode): React.ReactElement<Route>[] {
    return React.Children.toArray(children).flatMap(child => {
      if (!React.isValidElement(child)) return [];
      if (child.type === React.Fragment) return collect((child.props as { children?: React.ReactNode }).children);
      return [child as React.ReactElement<Route>];
    });
  }
  function Navigator({ children }: { children?: React.ReactNode }) {
    const routes = collect(children);
    const [chosen, setChosen] = React.useState<string | null>(null);
    const liveRoutes = React.useRef(routes); liveRoutes.current = routes;
    const navigation = React.useMemo(() => {
      const go = (name: string) => { if (liveRoutes.current.some(route => route.props.name === name)) setChosen(name); };
      return { navigate: go, replace: go, popToTop: () => setChosen(null) };
    }, []);
    React.useLayoutEffect(() => {
      const ref = { isReady: () => true, navigate: navigation.navigate };
      navigationRef.current = ref;
      return () => { if (navigationRef.current === ref) navigationRef.current = null; };
    }, [navigation]);
    const current = routes.find(route => route.props.name === chosen) ?? routes[0];
    if (!current) return null;
    const { component: Screen, options = {}, name } = current.props;
    return <>{options.headerShown !== false && <Text accessibilityRole="header">{options.title ?? name}</Text>}<Screen key={name} navigation={navigation} /></>;
  }
  return { createNativeStackNavigator: () => ({ Navigator, Screen: () => null }) };
});

import { AppNavigator, navigationRef } from "../src/navigation";
import { ThemeProvider } from "../src/theme";
import { SessionProvider } from "../src/store";
import { api } from "../src/api/client";
import { vault } from "../src/vault";
import { takePendingOnboarding } from "../src/onboarding";
import { takePendingNotificationRoute } from "../src/notificationRoute";
import storage from "./helpers/storageMock";
import * as keychain from "./helpers/keychainMock";
import * as files from "./helpers/expoFsMock";

const OWNER = "a".repeat(32), PASSWORD = "A real public navigation passphrase!", USERNAME = "public-question-navigation";
const SALT = Buffer.alloc(16, 27), TOKEN = "public-navigation-authenticated-bearer";
const MASTER = pbkdf2Sync(PASSWORD, SALT, 600_000, 32, "sha256");
const AUTH = Buffer.from(hkdfSync("sha256", MASTER, Buffer.alloc(32), "mindpattern/auth/v1", 32));
const DATA = Buffer.from(hkdfSync("sha256", MASTER, Buffer.alloc(32), "mindpattern/data/v1", 32)); MASTER.fill(0);
let root: TestRenderer.ReactTestRenderer | undefined;
const originalResponses: Promise<Response>[] = [];
let transportFault: unknown;
function setup(message: string, cause?: unknown) { return new Error("SetupError: public Question route producer: " + message, { cause }); }
function text(): string {
  const flatten = (value: unknown): string => Array.isArray(value) ? value.map(flatten).join("") : typeof value === "string" || typeof value === "number" ? String(value) : "";
  return root!.root.findAllByType(Text).map(node => flatten(node.props.children)).join(" ");
}
async function finite<T>(promise: Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([promise, new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(setup(label + " did not complete")), 15_000); })]); }
  finally { if (timer !== undefined) clearTimeout(timer); }
}
async function flush() { await act(async () => { for (let i = 0; i < 80; i++) await Promise.resolve(); }); }
async function until(predicate: () => boolean, label: string) {
  const deadline = Date.now() + 15_000;
  while (!predicate()) {
    if (transportFault) throw setup("unexpected authored transport outcome", transportFault);
    if (Date.now() >= deadline) throw setup(label + " was not reached");
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 5)); });
  }
}
function button(label: string) { return root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === label); }
async function producerPress(label: string) {
  const target = button(label); if (!target || target.props.disabled) throw setup("enabled public button missing: " + label);
  await act(async () => { await finite(Promise.resolve(target.props.onPress()), label); }); await flush();
}
function response(url: string, body: unknown, status = 200) {
  const result = new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  Object.defineProperty(result, "url", { value: url }); return result;
}

beforeEach(async () => {
  vi.useRealTimers(); vi.restoreAllMocks(); storage.__reset(); keychain.__reset(); files.__resetFiles();
  vault.lock(); await api.clearSession(); navigationRef.current = null; takePendingOnboarding(); takePendingNotificationRoute();
  originalResponses.length = 0; transportFault = undefined;
  vi.stubGlobal("fetch", (url: string, init: RequestInit) => {
    const pending = (async () => {
      const path = new URL(url).pathname, body = init.body ? JSON.parse(String(init.body)) as Record<string, unknown> : {};
      if (String(init.body ?? "").includes(PASSWORD)) throw setup("plaintext password reached transport");
      if (path.endsWith("/auth/salt")) return response(url, { salt: SALT.toString("base64") });
      if (path.endsWith("/auth/key-envelope")) return response(url, { code: "not_found", detail: "legacy account envelope absent" }, 404);
      if (path.endsWith("/auth/login")) {
        if (body.username !== USERNAME || body.verifier !== AUTH.toString("base64")) throw setup("Login verifier differs from independent600k credential");
        return response(url, { token: TOKEN, user_id: OWNER });
      }
      if (path.endsWith("/meta")) return response(url, { unlock_days: 30 });
      if (new Headers(init.headers).get("Authorization") !== "Bearer " + TOKEN) throw setup("request lacks actual adopted Login bearer");
      if (path.endsWith("/insights")) return response(url, { phase: "baseline", active_days: 0, days_remaining: 30 });
      if (path.endsWith("/progress")) return response(url, { active_days: 0 });
      if (path.endsWith("/entries") || path.endsWith("/measures") || path.endsWith("/consents")) return response(url, []);
      throw setup("unexpected native route request " + path);
    })();
    originalResponses.push(pending); void pending.catch(error => { transportFault = error; }); return pending;
  });
  await act(async () => { root = TestRenderer.create(<ThemeProvider><SessionProvider><AppNavigator /></SessionProvider></ThemeProvider>); });
  await until(() => Boolean(button("Sign in")), "actual logged-out Login");
  const username = root!.root.findAllByType(TextInput).find(node => node.props.placeholder === "username");
  const password = root!.root.findAllByType(TextInput).find(node => node.props.placeholder === "password");
  if (!username || !password) throw setup("public Login fields missing");
  await act(async () => { username.props.onChangeText(USERNAME); password.props.onChangeText(PASSWORD); });
  await producerPress("Sign in");
  await until(() => text().includes("Save entry") || text().includes("Write each day"), "actual first unlocked route");
  if (text().includes("Write each day")) {
    await producerPress("Continue to panel 2 of 3");
    await producerPress("Continue to panel 3 of 3");
    await producerPress("I understand — start writing");
  }
  await until(() => text().includes("Save entry"), "actual settled journal");
  if (!vault.isUnlocked() || vault.ownerUserId() !== OWNER || !vault.get().authKey.equals(AUTH) || !vault.get().dataKey.equals(DATA) || await api.getUserId() !== OWNER || !(await api.isLoggedIn())) throw setup("actual public Login/session/key owner differs from independent account");
  if (transportFault) throw setup("transport producer fault", transportFault);
});

afterEach(async () => {
  try {
    if (root) await act(async () => { root!.unmount(); root = undefined; });
    const results = await finite(Promise.allSettled(originalResponses), "owned original transport cleanup");
    const rejected = results.find((row): row is PromiseRejectedResult => row.status === "rejected");
    if (rejected) throw setup("original transport unexpectedly rejected", rejected.reason);
    if (transportFault) throw setup("unexpected native/public transport outcome", transportFault);
  } finally {
    try { vault.lock(); await api.clearSession(); }
    finally { navigationRef.current = null; takePendingOnboarding(); takePendingNotificationRoute(); vi.restoreAllMocks(); vi.unstubAllGlobals(); }
  }
});

it("the public Question tab opens the registered daily Question surface for the actual signed-in journal owner", async () => {
  const tab = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityRole === "tab" && node.props.accessibilityLabel === "Question");
  expect(tab).toBeDefined();
  await act(async () => { tab!.props.onPress(); }); await flush();
  // The native route host consumes the exact destination emitted by the
  // shipped BottomNav against the currently registered shipped stack.
  // This visible header assertion precedes any dependent Question wait.
  expect(root!.root.findAllByType(Text).filter(node => node.props.accessibilityRole === "header").map(node => node.props.children)).toEqual(["One question"]);
  expect(root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityRole === "tab" && node.props.accessibilityLabel === "Question")?.props.accessibilityState).toEqual({ selected: true });
  await until(() => Boolean(button("Write about this question")), "actual key-free Question content");
  expect(text()).toContain("Today's question");
  expect(text()).not.toContain("Save entry");
  expect(vault.ownerUserId()).toBe(OWNER);
  expect(await api.getUserId()).toBe(OWNER);
  expect(vault.get().dataKey.equals(DATA)).toBe(true);
  expect(await api.isLoggedIn()).toBe(true);
});
