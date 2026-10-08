import { readFileSync } from "node:fs";
import { dirname, resolve, extname } from "node:path";
import { createRequire } from "node:module";
const nativeRequire = createRequire(import.meta.url), babel = nativeRequire("@babel/core");
/** Loads the installed SDK, including validators and Promise couriers.
 * Only the OS module, platform and headless registration transports differ.
 * Actual RN EventEmitter/NativeEventEmitter implement constructor routing. */
export function installedNotifee(native: Record<string, unknown>) {
  const root = dirname(nativeRequire.resolve("@notifee/react-native/package.json")), rnRoot = dirname(nativeRequire.resolve("react-native/package.json"));
  const flow = (relative: string, dependency: (name: string) => unknown) => {
    const filename = resolve(rnRoot, relative), code = babel.transformSync(readFileSync(filename, "utf8"), { filename, babelrc: false, configFile: false, plugins: [nativeRequire.resolve("babel-plugin-syntax-hermes-parser"), nativeRequire.resolve("@babel/plugin-transform-flow-strip-types"), nativeRequire.resolve("@babel/plugin-transform-modules-commonjs")] })?.code;
    const module = { exports: {} as any }; new Function("require", "module", "exports", "__DEV__", code)(dependency, module, module.exports, false); return module.exports.default;
  };
  const EventEmitter = flow("Libraries/vendor/emitter/EventEmitter.js", name => { throw Error("Unmapped installed SDK emitter dependency " + name); });
  const deviceEmitter = new EventEmitter();
  const NativeEmitter = flow("Libraries/EventEmitter/NativeEventEmitter.js", name => {
    if (name.endsWith("/Platform")) return { __esModule: true, default: { OS: "android" } };
    if (name.endsWith("/RCTDeviceEventEmitter")) return { __esModule: true, default: deviceEmitter };
    if (name === "invariant") return nativeRequire(name);
    throw Error("Unmapped installed Native emitter dependency " + name);
  });
  const rn = { NativeModules: { NotifeeApiModule: native }, NativeEventEmitter: NativeEmitter, Platform: { OS: "android" }, AppRegistry: { registerHeadlessTask: () => {} }, Image: { resolveAssetSource: (source: unknown) => source } };
  const cache = new Map<string, { exports: any }>();
  const load = (path: string): any => {
    const filename = extname(path) ? path : (() => { try { readFileSync(path + ".js"); return path + ".js"; } catch { return resolve(path, "index.js"); } })();
    if (cache.has(filename)) return cache.get(filename)!.exports;
    const module = { exports: {} as any }; cache.set(filename, module);
    new Function("require", "module", "exports", readFileSync(filename, "utf8"))((name: string) => {
      if (name === "react-native") return rn;
      if (name === "react-native/Libraries/vendor/emitter/EventEmitter") return EventEmitter;
      if (name.startsWith(".")) return load(resolve(dirname(filename), name));
      throw Error("Unmapped installed Notifee dependency " + name);
    }, module, module.exports);
    return module.exports;
  };
  return load(resolve(root, "dist/index.js"));
}
