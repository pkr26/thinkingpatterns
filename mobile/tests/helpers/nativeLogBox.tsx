import React from "react";
import * as native from "react-native";
import { readFileSync, existsSync } from "node:fs";
import { dirname, resolve, extname } from "node:path";
import { createRequire } from "node:module";

/** Installed DEV ExceptionsManager → LogBox → LogBoxData → notification UI.
 * Only native host drawing, LogBox window transport, and the bundle's
 * SourceCode metadata are supplied by the test device. No log parser,
 * duplicate-key decision, observer, or notification component is mocked. */
export function installedNativeLogBox() {
  const requireNative = createRequire(import.meta.url);
  const babel = requireNative("@babel/core");
  const root = dirname(requireNative.resolve("react-native/package.json"));
  const cache = new Map<string, { exports: any }>();
  const deviceWindow = { visible: false };
  const platform = { OS: "ios", isTesting: false, select: (values: any) => values.ios ?? values.default };
  function load(filename: string): any {
    if (cache.has(filename)) return cache.get(filename)!.exports;
    if (/\.(png|jpg)$/.test(filename)) return { uri: "native-bundle:" + filename };
    const host = (value: any) => ({ __esModule: true, default: value });
    if (filename.endsWith("/Utilities/Platform.js")) return host(platform);
    if (filename.endsWith("/StyleSheet/StyleSheet.js")) return host({ ...native.StyleSheet, compose: (a: any, b: any) => a && b ? [a, b] : a || b });
    if (filename.endsWith("/Image/Image.js")) return host(native.View);
    if (filename.endsWith("/Text/Text.js")) return host(native.Text);
    if (filename.endsWith("/Components/View/View.js")) return host(native.View);
    if (filename.includes("/safeareaview/")) return host(native.View);
    if (/\/Components\/(?:Image|Touchable|Pressable)\//.test(filename)) return host(filename.includes("Image") ? native.View : native.TouchableOpacity);
    if (filename.endsWith("/Utilities/BackHandler.js")) return host({ addEventListener: () => ({ remove() {} }) });
    if (filename.endsWith("/Linking/Linking.js")) return host({ openURL: async () => {} });
    if (filename.endsWith("/specs/NativeLogBox.js")) return host({ show: () => { deviceWindow.visible = true; }, hide: () => { deviceWindow.visible = false; } });
    if (filename.endsWith("/specs/NativeSourceCode.js")) return host({ getConstants: () => ({ scriptURL: "file:///mindpattern.bundle" }) });
    if (filename.endsWith("/Utilities/NativeSourceCode.js")) return host({ getConstants: () => ({ scriptURL: "file:///mindpattern.bundle" }) });
    const module = { exports: {} as any }; cache.set(filename, module);
    const code = babel.transformSync(readFileSync(filename, "utf8"), { filename, babelrc: false, configFile: false, plugins: [requireNative.resolve("babel-plugin-syntax-hermes-parser"), requireNative.resolve("@babel/plugin-transform-flow-strip-types"), requireNative.resolve("@babel/plugin-transform-react-jsx"), requireNative.resolve("@babel/plugin-transform-modules-commonjs")] })?.code;
    if (!code) throw Error("Installed LogBox module did not load: " + filename);
    const dependency = (name: string) => {
      if (name === "react") return React;
      if (!name.startsWith(".")) return createRequire(filename)(name);
      let target = resolve(dirname(filename), name);
      if (!extname(target)) target += ".js";
      if (!existsSync(target)) throw Error("Missing installed LogBox dependency " + target);
      return load(target);
    };
    new Function("require", "module", "exports", "__DEV__", "global", code)(dependency, module, module.exports, true, globalThis);
    return module.exports;
  }
  const LogBox = load(resolve(root, "Libraries/LogBox/LogBox.js")).default;
  const data = load(resolve(root, "Libraries/LogBox/Data/LogBoxData.js"));
  const ExceptionsManager = load(resolve(root, "Libraries/Core/ExceptionsManager.js")).default;
  const Tray = load(resolve(root, "Libraries/LogBox/LogBoxNotificationContainer.js")).default;
  const originalError = Object.getOwnPropertyDescriptor(console, "error")!;
  const originalWarn = Object.getOwnPropertyDescriptor(console, "warn")!;
  const originalPrivate = Object.getOwnPropertyDescriptor(console, "_errorOriginal");
  const originalAct = Object.getOwnPropertyDescriptor(globalThis, "IS_REACT_ACT_ENVIRONMENT");
  const originalReport = Object.getOwnPropertyDescriptor(console, "reportErrorsAsExceptions");
  let stopPromiseTracker: (() => void) | undefined;
  return {
    Tray,
    clearLogs() { LogBox.clearAllLogs(); },
    /** The device engine delivers its genuine unhandled-Promise event to the
     * tracker registered by the installed RN bootstrap. Node supplies the
     * engine event transport here; RN formats, reports, and renders it. Tests
     * must neither invoke the tracker callbacks nor infer an outcome from an
     * engine listener count. */
    trackUnhandledPromises() {
      if (stopPromiseTracker) throw Error("Native Promise tracker is already installed");
      const originalHermes = Object.getOwnPropertyDescriptor(globalThis, "HermesInternal");
      let options: { onUnhandled(id: number, rejection: unknown): void; onHandled(id: number): void } | undefined;
      Object.defineProperty(globalThis, "HermesInternal", { configurable: true, writable: true, value: {
        hasPromise: () => true,
        enablePromiseRejectionTracker: (registered: typeof options) => { options = registered; },
      } });
      load(resolve(root, "Libraries/Core/polyfillPromise.js"));
      if (!options) throw Error("Installed RN bootstrap did not register its Promise tracker");
      let nextId = 0;
      const ids = new WeakMap<Promise<unknown>, number>();
      const unhandled = (rejection: unknown, promise: Promise<unknown>) => {
        const id = ++nextId; ids.set(promise, id); options!.onUnhandled(id, rejection);
      };
      const handled = (promise: Promise<unknown>) => {
        const id = ids.get(promise); if (id !== undefined) options!.onHandled(id);
      };
      process.on("unhandledRejection", unhandled);
      process.on("rejectionHandled", handled);
      stopPromiseTracker = () => {
        process.removeListener("unhandledRejection", unhandled);
        process.removeListener("rejectionHandled", handled);
        if (originalHermes) Object.defineProperty(globalThis, "HermesInternal", originalHermes); else delete (globalThis as any).HermesInternal;
        stopPromiseTracker = undefined;
      };
      return () => stopPromiseTracker?.();
    },
    start() {
      (globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;
      delete (console as any)._errorOriginal;
      (console as any).reportErrorsAsExceptions = true;
      LogBox.install(); ExceptionsManager.installConsoleErrorReporter();
    },
    dispose() {
      stopPromiseTracker?.();
      LogBox.uninstall(); data.clear();
      if (originalAct) Object.defineProperty(globalThis, "IS_REACT_ACT_ENVIRONMENT", originalAct); else delete (globalThis as any).IS_REACT_ACT_ENVIRONMENT;
      Object.defineProperty(console, "error", originalError);
      Object.defineProperty(console, "warn", originalWarn);
      if (originalPrivate) Object.defineProperty(console, "_errorOriginal", originalPrivate); else delete (console as any)._errorOriginal;
      if (originalReport) Object.defineProperty(console, "reportErrorsAsExceptions", originalReport); else delete (console as any).reportErrorsAsExceptions;
    },
  };
}
