import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Mutation instrumentation is confined to a disposable copy. Shared vectors
// keep their expected sibling location; native build caches are unnecessary.
const mobile = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const canariesOnly = process.argv.includes("--canaries-only");
const baselineOnly = process.argv.includes("--baseline-only");
const campaignArgs = process.argv.slice(2).filter(arg => !["--canaries-only", "--baseline-only"].includes(arg));
const scratch = mkdtempSync(join(tmpdir(), "mindpattern-mobile-mutation-"));
const isolated = join(scratch, "mobile");
// Stryker's Babel 8 parser must not load Metro's Babel 7 transforms. Vitest
// executes this campaign through Oxc; the three entry sources stay byte exact.
const excluded = new Set(["node_modules", "reports", "coverage", "stryker-tmp", ".stryker-tmp", ".gradle", "build", "Pods", "babel.config.cjs"]);
cpSync(mobile, isolated, { recursive: true, filter: path => !relative(mobile, path).split(/[\\/]/).some(part => excluded.has(part)) });
cpSync(join(mobile, "..", "shared"), join(scratch, "shared"), { recursive: true });
symlinkSync(join(mobile, "node_modules"), join(isolated, "node_modules"), "dir");

// JSON selectors also preserve brace globs that contain commas.
const selectedTests = process.env.MOBILE_MUTATION_TEST_FILES_JSON
  ? JSON.parse(process.env.MOBILE_MUTATION_TEST_FILES_JSON)
  : process.env.MOBILE_MUTATION_TEST_FILES?.split(",").filter(Boolean);
const selectedNamePattern = process.env.MOBILE_MUTATION_TEST_NAME_PATTERN || undefined;
const selectedSetup = process.env.MOBILE_MUTATION_SETUP_FILES_JSON ? JSON.parse(process.env.MOBILE_MUTATION_SETUP_FILES_JSON) : undefined;
const workerCachePrefix = join(isolated, ".campaign-cache");
{
  // Each Stryker worker has private runtime state. Keep persistent runner
  // metadata private too: node_modules is shared with other disposable lanes.
  writeFileSync(join(isolated, "vitest.shard.config.ts"), `import base from "./vitest.mutation.config";\nexport default { ...base, cacheDir: ${JSON.stringify(workerCachePrefix)} + "-" + (process.env.STRYKER_MUTATOR_WORKER ?? "baseline"), test: { ...base.test, cache: false, testTimeout: 120000, hookTimeout: 120000, update: "none", include: ${selectedTests ? JSON.stringify(selectedTests) : "base.test?.include"}${selectedNamePattern ? `, testNamePattern: ${JSON.stringify(selectedNamePattern)}` : ""}${selectedSetup ? `, setupFiles: ${JSON.stringify(selectedSetup)}` : ""} } };\n`);
  const configPath = join(isolated, "stryker.config.json");
  const config = JSON.parse(readFileSync(configPath, "utf8"));
  config.vitest.configFile = "./vitest.shard.config.ts";
  // The selected public-consumer suite is authoritative. Native/bootstrap
  // harnesses load real sources outside Vite's import graph, so related-test
  // discovery cannot reliably recognize their dependency on these targets.
  config.vitest.related = false;
  writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n");
}

const output = resolve(mobile, process.env.MOBILE_MUTATION_REPORT_DIR || "reports/mutation");
mkdirSync(output, { recursive: true });
// The shard orchestrator opens the current run.log before launching this
// process. Every retained execution receipt/report must remain immutable.
if (readdirSync(output).some(name => name !== "run.log")) throw new Error(`Campaign output directory must be fresh: ${output}`);
function walk(directory) { return readdirSync(directory, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? walk(join(directory, entry.name)) : [join(directory, entry.name)]); }
const hash = path => createHash("sha256").update(readFileSync(path)).digest("hex");
const hashFiles = (root, files) => Object.fromEntries(files.sort().map(path => [relative(root, path), hash(path)]));
const productionFiles = () => [join(isolated, "App.tsx"), join(isolated, "index.js"), join(isolated, "installPolyfills.cjs"), ...walk(join(isolated, "src")).filter(path => /\.[cm]?[jt]sx?$/.test(path))];
const manifest = hashFiles(isolated, productionFiles());
const testManifest = hashFiles(isolated, walk(join(isolated, "tests")));
const sharedManifest = hashFiles(scratch, walk(join(scratch, "shared")));
const configFiles = ["package.json", "package-lock.json", "stryker.config.json", "vitest.config.ts", "vitest.mutation.config.ts", "vitest.shard.config.ts"].map(file => join(isolated, file));
const configManifest = hashFiles(isolated, configFiles);
const toolsManifest = hashFiles(isolated, walk(join(isolated, "tools")));
const dependencyFiles = ["@stryker-mutator/core", "@stryker-mutator/vitest-runner", "@stryker-mutator/instrumenter", "vitest"].map(name => join(isolated, "node_modules", name, "package.json"));
writeFileSync(join(output, "execution.json"), JSON.stringify({ isolated, argv: process.argv.slice(2), selectedTests, selectedNamePattern, supportIsolation: { resultsCache: false, workerCachePrefix }, sourceHashes: manifest, testHashes: testManifest, sharedHashes: sharedManifest, configHashes: configManifest, toolsHashes: toolsManifest, dependencyHashes: hashFiles(isolated, dependencyFiles), nodeVersion: process.version, startedAt: new Date().toISOString() }, null, 2) + "\n");
console.log(`Mutation working copy: ${isolated}`);
const runEnvironment = { ...process.env, MOBILE_UPDATE_PUBLIC_SURFACES: "" };
const stryker = join(isolated, "node_modules", "@stryker-mutator", "core", "bin", "stryker.js");
// Qualify the exact runner used by this disposable lane. A control must be
// executed, restore its inputs, and distinguish an assertion failure from a
// deliberate survivor; infrastructure failures never earn kill credit.
const witnessSource = 'export const staticKill = "protected-banner";\nexport const staticSurvivor = "loose-caption";\nexport function runtimeKill() { return "ready"; }\nexport function runtimeSurvivor() { return "loose"; }\nexport const snapshotKill = "protected snapshot";\nexport function closureKill() { return () => false; }\n';
const witnessTests = 'import {expect,it} from "vitest"; import {staticKill,staticSurvivor,runtimeKill,runtimeSurvivor,snapshotKill,closureKill} from "../tools/mutation-runner-canaries"; it("static exact output",()=>expect(staticKill).toBe("protected-banner")); it("static deliberate survivor",()=>expect(typeof staticSurvivor).toBe("string")); it("runtime exact output",()=>expect(runtimeKill()).toBe("ready")); it("runtime deliberate survivor",()=>expect(typeof runtimeSurvivor()).toBe("string")); it("snapshot output",()=>expect(snapshotKill).toMatchSnapshot()); it("runtime closure output",()=>expect(closureKill()()).toBe(false));\n';
const witnessSnapshot = '// Vitest Snapshot v1\n\nexports[`snapshot output 1`] = `"protected snapshot"`;\n';
const witnessFiles = {
  "tools/mutation-runner-canaries.ts": witnessSource,
  "tests/mutation-runner-canaries.test.ts": witnessTests,
  "tests/__snapshots__/mutation-runner-canaries.test.ts.snap": witnessSnapshot,
  "mutation-canary.vitest.config.ts": 'import base from "./vitest.mutation.config"; export default {...base,cacheDir:".canary-cache-"+(process.env.STRYKER_MUTATOR_WORKER??"baseline"),test:{...base.test,cache:false,update:"none",include:["tests/mutation-runner-canaries.test.ts"],coverage:{...base.test?.coverage,enabled:false}}};\n',
};
for (const [file, content] of Object.entries(witnessFiles)) {
  mkdirSync(dirname(join(isolated, file)), { recursive: true });
  writeFileSync(join(isolated, file), content);
}
const canaryReportPath = join(output, "runner-canaries.json");
rmSync(canaryReportPath, { force: true });
const campaignConfig = JSON.parse(readFileSync(join(isolated, "stryker.config.json"), "utf8"));
writeFileSync(join(isolated, "mutation-canary.config.json"), JSON.stringify({ ...campaignConfig, mutate: ["tools/mutation-runner-canaries.ts"], inPlace: true, concurrency: 1, timeoutMS: 2000, vitest: { related: false, configFile: "mutation-canary.vitest.config.ts" }, reporters: ["json", "clear-text"], appendPlugins: [], thresholds: { break: 0 }, jsonReporter: { fileName: canaryReportPath } }, null, 2));
const controls = spawnSync(process.execPath, [stryker, "run", "mutation-canary.config.json"], { cwd: isolated, stdio: "inherit", env: runEnvironment });
if (controls.status !== 0 || !existsSync(canaryReportPath)) throw new Error(`Runner qualification failed: exit ${controls.status}, signal ${controls.signal}`);
const canaryReport = JSON.parse(readFileSync(canaryReportPath, "utf8"));
const canaries = Object.values(canaryReport.files).flatMap(file => file.mutants);
const expectedControls = [
  [1, "StringLiteral", "Killed", true], [2, "StringLiteral", "Survived", true],
  [3, "BlockStatement", "Killed", false], [3, "StringLiteral", "Killed", false],
  [4, "BlockStatement", "Killed", false], [4, "StringLiteral", "Survived", false],
  [5, "StringLiteral", "Killed", true],
  [6, "BlockStatement", "Killed", false], [6, "ArrowFunction", "Killed", false], [6, "BooleanLiteral", "Killed", false],
];
if (canaries.length !== expectedControls.length || expectedControls.some(([line, operator, status, isStatic]) => !canaries.some(mutant => mutant.location.start.line === line && mutant.mutatorName === operator && mutant.status === status && mutant.static === isStatic && mutant.testsCompleted > 0))) throw new Error(`Runner did not distinguish all executed kill and survivor controls: ${canaryReportPath}`);
for (const [file, content] of Object.entries(witnessFiles)) if (readFileSync(join(isolated, file), "utf8") !== content) throw new Error(`Runner qualification changed its input: ${file}`);
writeFileSync(join(output, "runner-qualification.json"), JSON.stringify({ passed: true, controls: expectedControls.length, sourceRestored: true, snapshotRestored: true, reportSha256: hash(canaryReportPath), completedAt: new Date().toISOString() }, null, 2) + "\n");
for (const file of [...Object.keys(witnessFiles), "mutation-canary.config.json"]) rmSync(join(isolated, file));
function restoration() {
  const restoredHashes = hashFiles(isolated, productionFiles());
  const sourceRestored = JSON.stringify(restoredHashes) === JSON.stringify(manifest);
  const testsRestored = JSON.stringify(hashFiles(isolated, walk(join(isolated, "tests")))) === JSON.stringify(testManifest);
  const sharedRestored = JSON.stringify(hashFiles(scratch, walk(join(scratch, "shared")))) === JSON.stringify(sharedManifest);
  const configRestored = JSON.stringify(hashFiles(isolated, configFiles)) === JSON.stringify(configManifest);
  const toolsRestored = JSON.stringify(hashFiles(isolated, walk(join(isolated, "tools")))) === JSON.stringify(toolsManifest);
  return { restored: sourceRestored && testsRestored && sharedRestored && configRestored && toolsRestored, sourceRestored, testsRestored, sharedRestored, configRestored, toolsRestored, restoredHashes };
}
function finish(result, phase) {
  const restored = restoration();
  writeFileSync(join(output, "exit.json"), JSON.stringify({ status: result.status, signal: result.signal, error: result.error?.message, phase, completedAt: new Date().toISOString(), isolated, ...restored }, null, 2) + "\n");
  if (!restored.restored) console.error("The isolated source, test oracles or shared fixtures changed; this execution needs review.");
  if (result.error) console.error(result.error);
  process.exit(restored.restored ? result.status ?? 1 : 1);
}
if (canariesOnly) finish(controls, "qualification");
const baselinePath = join(output, "baseline.json");
rmSync(baselinePath, { force: true });
const baseline = spawnSync(process.execPath, [join(isolated, "node_modules", "vitest", "vitest.mjs"), "run", "--config", "vitest.shard.config.ts", "--coverage.enabled=false", "--maxWorkers=2", "--reporter=json", "--outputFile", baselinePath], { cwd: isolated, stdio: "inherit", env: runEnvironment });
if (baseline.status !== 0 || !existsSync(baselinePath) || !JSON.parse(readFileSync(baselinePath, "utf8")).numPassedTests) throw new Error(`Pristine mutation selector baseline failed or ran zero tests: ${baselinePath}`);
if (!restoration().restored) finish({ status: 1 }, "baseline-input-failure");
if (baselineOnly) finish(baseline, "baseline");
const result = spawnSync(process.execPath, [stryker, "run", ...campaignArgs, "--inPlace"], { cwd: isolated, stdio: "inherit", env: { ...runEnvironment, MOBILE_MUTATION_EVENT_FILE: join(output, "mutants.jsonl") } });
for (const file of ["mutation.json", "mutation.html"]) {
  const report = join(isolated, "reports", "mutation", file);
  if (existsSync(report)) cpSync(report, join(output, file));
}
finish(result, "mutation");
