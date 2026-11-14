import { beforeEach, expect, it, vi } from "vitest";
beforeEach(()=>{vi.resetModules();});

it("rejects an empty journal within a finite pattern-check budget", async () => {
  const { detectCrisisLanguage } = await import("../src/crisisDetect");
  const test = RegExp.prototype.test;
  let checks = 0;
  const guarded = vi.spyOn(RegExp.prototype, "test").mockImplementation(function (
    this: RegExp, input: string
  ) {
    if (++checks > 4096) throw new Error("Empty journal detection exceeded its finite pattern-check budget");
    return Reflect.apply(test, this, [input]) as boolean;
  });
  let detected: boolean;
  try {
    detected = detectCrisisLanguage("");
  } finally {
    guarded.mockRestore();
  }
  expect(detected).toBe(false);
});
it("fully normalizes the public leet phrase before returning", async () => {
  const { normalizeCrisisText } = await import("../src/crisisDetect");
  expect(normalizeCrisisText("su1c1de")).toBe("suicide");
});

it("finishes a short fixed-point input within a finite string-transform budget", async () => {
  const { normalizeCrisisText } = await import("../src/crisisDetect");
  const replace = String.prototype.replace;
  let transforms = 0;
  const guarded = vi.spyOn(String.prototype, "replace").mockImplementation(function (
    this: string, ...args: Parameters<String["replace"]>
  ) {
    // A short unchanged word must reach its fixed point. This generous
    // operation bound makes a convergence failure deterministic, without
    // waiting for the test runner's wall-clock watchdog.
    if (++transforms > 256 || this.length > 4096) {
      throw new Error("Short crisis normalization exceeded its finite transform budget");
    }
    return Reflect.apply(replace, this, args) as string;
  });
  let normalized: string;
  try {
    normalized = normalizeCrisisText("suicide");
  } finally {
    guarded.mockRestore();
  }
  expect(normalized).toBe("suicide");
});
it("matches a short literal without unbounded expansion",async()=>{
  const {normalizeCrisisText,detectCrisisLanguage}=await import("../src/crisisDetect");
  expect(normalizeCrisisText("suicide")).toBe("suicide");
  expect(detectCrisisLanguage("suicide")).toBe(true);
});
it("normalizes empty journal text without allocating an expanded result",async()=>{
  const {normalizeCrisisText,detectCrisisLanguage}=await import("../src/crisisDetect");
  expect(normalizeCrisisText("")).toBe("");
  expect(detectCrisisLanguage("")).toBe(false);
});
