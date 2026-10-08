import { beforeEach, expect, it, vi } from "vitest";
beforeEach(()=>{vi.resetModules();});
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
