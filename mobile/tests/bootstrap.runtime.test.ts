import { readFileSync } from "node:fs";
import { runInThisContext } from "node:vm";
import { describe, expect, it, vi } from "vitest";

// Execute the shipped CommonJS entry in this process: Stryker's instrumented
// globals remain available, and these tests assert its effects, not its text.
function execute(file: string, requireModule: (id: string) => unknown): void {
  const source = readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
  const executeModule = runInThisContext(`(function(require, module, exports) { ${source}\n })`, { filename: file });
  const module = { exports: {} };
  executeModule(requireModule, module, module.exports);
}

describe("native bootstrap runtime", () => {
  it("installs crypto before evaluating App and registers the application factory", () => {
    const order: string[] = [];
    const app = () => null;
    const registerComponent = vi.fn((name: string, factory: () => unknown) => {
      order.push("register");
      expect(name).toBe("MindPattern");
      expect(factory()).toBe(app);
    });
    execute("index.js", id => {
      if (id === "./installPolyfills.cjs") { order.push("install"); return {}; }
      if (id === "react-native") return { AppRegistry: { registerComponent } };
      if (id === "./App") { expect(order).toEqual(["install"]); order.push("App"); return { default: app }; }
      throw new Error(`Unexpected entry dependency: ${id}`);
    });
    expect(order).toEqual(["install", "App", "register"]);
    expect(registerComponent).toHaveBeenCalledTimes(1);
  });

  it.each(["default", "commonjs"])("installs the %s crypto export synchronously", shape => {
    const install = vi.fn();
    const backend = { install };
    execute("installPolyfills.cjs", id => {
      if (id !== "react-native-quick-crypto") throw new Error(`Unexpected crypto dependency: ${id}`);
      return shape === "default" ? { default: backend } : backend;
    });
    expect(install).toHaveBeenCalledTimes(1);
  });
});
