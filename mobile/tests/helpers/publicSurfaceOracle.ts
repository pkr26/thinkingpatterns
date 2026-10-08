import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { gzipSync, gunzipSync } from "node:zlib";
import { afterAll, expect } from "vitest";

type ApprovedSurfaces = { stages: Record<string, number>; trees: unknown[] };
function surfaceDifference(actual: unknown, expected: unknown, path = "$surface"): string | undefined {
  if (Object.is(actual, expected)) return;
  if (Array.isArray(actual) && Array.isArray(expected)) {
    if (actual.length !== expected.length) return `${path}.length: expected ${expected.length}, actual ${actual.length}`;
    for (let index = 0; index < actual.length; index++) { const difference = surfaceDifference(actual[index], expected[index], `${path}[${index}]`); if (difference) return difference; }
    return;
  }
  if (actual && expected && typeof actual === "object" && typeof expected === "object") {
    const keys = new Set([...Object.keys(actual), ...Object.keys(expected)]);
    for (const key of keys) {
      const difference = surfaceDifference((actual as Record<string, unknown>)[key], (expected as Record<string, unknown>)[key], `${path}.${key}`);
      if (difference) return difference;
    }
    return;
  }
  return `${path}: expected ${JSON.stringify(expected)}, actual ${JSON.stringify(actual)}`;
}
const fixtures = new Map<string, ApprovedSurfaces>();
const capture = process.env.MOBILE_UPDATE_PUBLIC_SURFACES === "1";
if (capture && process.env.MOBILE_MUTATION_EVENT_FILE) throw new Error("Mutation runs must never update public UI expectations");
function writeCapturedSurfaces(): void {
  if (!capture) return;
  for (const [file, approved] of fixtures) {
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, gzipSync(JSON.stringify({ contract: "Reviewed rendered native text, accessibility values and flattened styles; public scenario stages preserve every assertion, sharing identical approved trees.", ...approved }) + "\n"));
  }
}
afterAll(writeCapturedSurfaces);
// Some locale scenarios import their rendering helpers after the test has
// started. Setup's early afterEach hook still persists that capture.
if (capture) (globalThis as Record<symbol, (() => void) | undefined>)[Symbol.for("mindpattern.test.flushPublicSurfaces")] = writeCapturedSurfaces;

export function assertPublicSurface(actual: unknown, stage: number): void {
  const { testPath, currentTestName } = expect.getState();
  if (!testPath || !currentTestName) throw new Error("Public surface assertions require a running behavioral test");
  const file = join(dirname(testPath), "__snapshots__", `${basename(testPath)}.public.json.gz`);
  let approved = fixtures.get(file);
  if (!approved) {
    approved = capture ? { stages: {}, trees: [] } : JSON.parse(gunzipSync(readFileSync(file)).toString("utf8")) as ApprovedSurfaces;
    fixtures.set(file, approved);
  }
  const key = `${currentTestName.replaceAll(" > ", " ")} rendered native surface ${stage}`;
  if (capture) {
    const clean = JSON.parse(JSON.stringify(actual));
    const serialized = JSON.stringify(clean);
    let id = approved.trees.findIndex(tree => JSON.stringify(tree) === serialized);
    if (id < 0) { id = approved.trees.length; approved.trees.push(clean); }
    approved.stages[key] = id;
    return;
  }
  const id = approved.stages[key];
  if (id === undefined) throw new Error(`Missing approved public native surface: ${key}`);
  const difference = surfaceDifference(actual, approved.trees[id]);
  expect(actual, difference ? `${key}: ${difference}` : key).toEqual(approved.trees[id]);
}
