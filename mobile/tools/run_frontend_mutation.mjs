import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Mutation instrumentation is confined to a disposable copy. Shared vectors
// keep their expected sibling location; native build caches are unnecessary.
const mobile = resolve(dirname(fileURLToPath(import.meta.url)), "..");
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
if (selectedTests) {
  writeFileSync(join(isolated, "vitest.shard.config.ts"), `import base from "./vitest.mutation.config";\nexport default { ...base, test: { ...base.test, testTimeout: 120000, hookTimeout: 120000, update: "none", include: ${JSON.stringify(selectedTests)}${selectedNamePattern ? `, testNamePattern: ${JSON.stringify(selectedNamePattern)}` : ""}${selectedSetup ? `, setupFiles: ${JSON.stringify(selectedSetup)}` : ""} } };\n`);
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
function walk(directory) { return readdirSync(directory, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? walk(join(directory, entry.name)) : [join(directory, entry.name)]); }
const hash = path => createHash("sha256").update(readFileSync(path)).digest("hex");
const hashFiles = (root, files) => Object.fromEntries(files.sort().map(path => [relative(root, path), hash(path)]));
const productionFiles = [join(isolated, "App.tsx"), join(isolated, "index.js"), join(isolated, "installPolyfills.cjs"), ...walk(join(isolated, "src")).filter(path => /\.[cm]?[jt]sx?$/.test(path))];
const manifest = hashFiles(isolated, productionFiles);
const configFiles = ["package.json", "package-lock.json", "stryker.config.json", "vitest.config.ts", "vitest.mutation.config.ts", ...(selectedTests ? ["vitest.shard.config.ts"] : [])].map(file => join(isolated, file));
const dependencyFiles = ["@stryker-mutator/core", "@stryker-mutator/vitest-runner", "@stryker-mutator/instrumenter", "vitest"].map(name => join(isolated, "node_modules", name, "package.json"));
writeFileSync(join(output, "execution.json"), JSON.stringify({ isolated, argv: process.argv.slice(2), selectedTests, selectedNamePattern, sourceHashes: manifest, testHashes: hashFiles(isolated, walk(join(isolated, "tests"))), sharedHashes: hashFiles(scratch, walk(join(scratch, "shared"))), configHashes: hashFiles(isolated, configFiles), dependencyHashes: hashFiles(isolated, dependencyFiles), nodeVersion: process.version, startedAt: new Date().toISOString() }, null, 2) + "\n");
console.log(`Mutation working copy: ${isolated}`);
const result = spawnSync(process.execPath, [join(isolated, "node_modules", "@stryker-mutator", "core", "bin", "stryker.js"), "run", ...process.argv.slice(2), "--inPlace"], { cwd: isolated, stdio: "inherit", env: { ...process.env, MOBILE_UPDATE_PUBLIC_SURFACES: "", MOBILE_MUTATION_EVENT_FILE: join(output, "mutants.jsonl") } });
for (const file of ["mutation.json", "mutation.html"]) {
  const report = join(isolated, "reports", "mutation", file);
  if (existsSync(report)) cpSync(report, join(output, file));
}
const restoredHashes = hashFiles(isolated, productionFiles);
const restored = JSON.stringify(restoredHashes) === JSON.stringify(manifest);
writeFileSync(join(output, "exit.json"), JSON.stringify({ status: result.status, signal: result.signal, error: result.error?.message, completedAt: new Date().toISOString(), isolated, restored, restoredHashes }, null, 2) + "\n");
if (!restored) console.error("The isolated source was not restored to its pre-run snapshot; this execution needs review.");
if (result.error) console.error(result.error);
process.exit(restored ? result.status ?? 1 : 1);
