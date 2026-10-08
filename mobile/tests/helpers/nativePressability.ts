import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { createRequire } from "node:module";

const requireNative = createRequire(import.meta.url);
const babel = requireNative("@babel/core") as { transformSync(source: string, options: Record<string, unknown>): { code?: string } | null };
const nativeRoot = dirname(requireNative.resolve("react-native/package.json"));
let Pressability: any;
export function installedPressability() {
  if (Pressability) return Pressability;
  const filename = resolve(nativeRoot, "Libraries/Pressability/Pressability.js");
  const code = babel.transformSync(readFileSync(filename, "utf8"), { filename, babelrc: false, configFile: false, plugins: [requireNative.resolve("babel-plugin-syntax-hermes-parser"), requireNative.resolve("@babel/plugin-transform-flow-strip-types"), requireNative.resolve("@babel/plugin-transform-modules-commonjs")] })?.code;
  if (!code) throw new Error("Installed Native press responder could not be loaded");
  const module = { exports: {} as any };
  const dependency = (name: string) => {
    if (name.endsWith("ReactNativeFeatureFlags")) return new Proxy({}, { get: () => () => false });
    if (name.endsWith("SoundManager")) return { playTouchSound: () => {} };
    if (name.endsWith("UIManager")) return { measure: (_tag: unknown, callback: (...args: number[]) => void) => callback(0, 0, 320, 80, 0, 0) };
    if (name.endsWith("/Rect")) return { normalizeRect: (rect: unknown) => rect };
    if (name.endsWith("/Platform")) return { OS: "ios" };
    if (name.endsWith("/HoverState")) return { isHoverEnabled: () => false };
    if (name.endsWith("PressabilityPerformanceEventEmitter.js")) return { emitEvent: () => {} };
    return requireNative(name);
  };
  // Execute the installed Native responder state machine; only Flow/module
  // syntax is transformed. Platform measurement/sound remain Native seams.
  new Function("require", "module", "exports", "__DEV__", code)(dependency, module, module.exports, true);
  Pressability = module.exports.default;
  return Pressability;
}

/** A touch granted while enabled can release after React replaces config. */
export function nativeGrantedPress(props: { disabled?: boolean; onPress: () => void }) {
  const NativePressability = installedPressability();
  const responder = new NativePressability({ ...props, delayLongPress: 60_000 });
  const handlers = responder.getEventHandlers();
  const event = { currentTarget: 1, target: 1, persist: () => {}, nativeEvent: { pageX: 10, pageY: 10, locationX: 10, locationY: 10, timestamp: Date.now(), touches: [{ pageX: 10, pageY: 10 }] } };
  if (!handlers.onStartShouldSetResponder(event)) throw new Error("Native touch was not admitted");
  handlers.onResponderGrant(event);
  return {
    configure: (next: { disabled?: boolean; onPress: () => void }) => responder.configure({ ...next, delayLongPress: 60_000 }),
    release: () => handlers.onResponderRelease(event),
    dispose: () => responder.reset(),
  };
}
