/** Execute pinned RN Switch and ref hooks unchanged apart from syntax lowering.
 * Native host/commands/platform are the only switch-specific runtime substitutes.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { createElement, type ComponentType } from "react";
import type { ReactTestRenderer } from "react-test-renderer";

const requireNative = createRequire(import.meta.url);
const babel = requireNative("@babel/core") as { transformSync(source: string, options: Record<string, unknown>): { code?: string } | null };
const nativeRoot = dirname(requireNative.resolve("react-native/package.json"));
type Props = { disabled?: boolean; value?: boolean; onValueChange?: (value: boolean) => void; [key: string]: unknown };
export const SWITCH_NATIVE_HOST = (props: Props) => createElement("input", props);
const compiled = new Map<string, { exports: Record<string, unknown> }>();
const evidence: Record<string, { sourceSha256: string; transformedSha256: string }> = {};
const hash = (bytes: string | Buffer) => createHash("sha256").update(bytes).digest("hex");

function compile(relative: string): Record<string, unknown> {
  const filename = resolve(nativeRoot, relative), previous = compiled.get(filename);
  if (previous) return previous.exports;
  const source = readFileSync(filename, "utf8");
  const code = babel.transformSync(source, {
    filename, babelrc: false, configFile: false,
    plugins: [requireNative.resolve("babel-plugin-syntax-hermes-parser"), requireNative.resolve("@babel/plugin-transform-flow-strip-types"), requireNative.resolve("@babel/plugin-transform-react-jsx"), requireNative.resolve("@babel/plugin-transform-modules-commonjs")],
  })?.code;
  if (!code) throw new Error("SetupError: actual installed Switch syntax lowering unavailable");
  const module = { exports: {} as Record<string, unknown> }; compiled.set(filename, module);
  const dependency = (name: string): unknown => {
    if (name === "react") return requireNative(name);
    if (name.endsWith("/Platform")) return { OS: "android" };
    if (name.endsWith("/StyleSheet")) return { compose: (left: unknown, right: unknown) => [left, right] };
    if (name.endsWith("AndroidSwitchNativeComponent") || name.endsWith("/SwitchNativeComponent")) {
      return { __esModule: true, default: SWITCH_NATIVE_HOST, Commands: { setNativeValue: () => {}, setValue: () => {} } };
    }
    if (name.endsWith("useMergeRefs")) return compile("Libraries/Utilities/useMergeRefs.js");
    if (name.endsWith("useRefEffect")) return compile("Libraries/Utilities/useRefEffect.js");
    throw new Error("SetupError: unexpected actual Switch runtime dependency: " + name);
  };
  try { new Function("require", "module", "exports", "__DEV__", code)(dependency, module, module.exports, true); }
  catch (error) { throw new Error("SetupError: installed Switch evaluation failed", { cause: error }); }
  evidence[relative] = { sourceSha256: hash(source), transformedSha256: hash(code) };
  return module.exports;
}

export function installedNativeSwitch(): ComponentType<Props> {
  return compile("Libraries/Components/Switch/Switch.js").default as ComponentType<Props>;
}

export function installedSwitchEvidence() {
  return { nativeRoot, compiledVendorSources: { ...evidence }, nativePlatform: "android", originalVendorHandlersExecuted: true,
    loadedCompilerRuntimeHashes: Object.fromEntries(Object.keys(requireNative.cache).filter(path => path.includes("/node_modules/") && path.endsWith(".js")).sort().map(path => [path, hash(readFileSync(path))])) };
}

/** A lower native transport stores ONLY the payload, never a JS callback.
 * Its later listener lookup is against the current mounted host props, matching
 * the shipping Fabric renderer. The event must be admitted while enabled.
 */
export function admitQueuedSwitchPayload(root: ReactTestRenderer, value: boolean) {
  const admitted = root.root.find(node => node.type === SWITCH_NATIVE_HOST);
  if (admitted.props.enabled !== true) throw new Error("SetupError: native Switch payload was not admitted while enabled");
  const event = { nativeEvent: { target: 1, value } };
  let delivered = false;
  return {
    payload: event.nativeEvent,
    deliverToCurrentHost() {
      if (delivered) throw new Error("SetupError: native Switch payload delivered twice");
      const current = root.root.find(node => node.type === SWITCH_NATIVE_HOST);
      if (current !== admitted || typeof current.props.onChange !== "function") throw new Error("SetupError: queued Switch target no longer mounted/current");
      delivered = true;
      current.props.onChange(event);
      return { delivered, currentNativeEnabled: current.props.enabled, listenerResolvedFromCurrentProps: true };
    },
  };
}
