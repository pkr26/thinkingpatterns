import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { mutantKey } from "../../tools/audit-frontend-mutation.mjs";

const [input, output, selectors, workers = "2", timeout = "6000"] = process.argv.slice(2);
if (!input || !output || !selectors) throw new Error("Usage: replay_mutation_survivors.mjs report.json output-dir selectors-json [workers] [timeoutMS]");
const bytes = readFileSync(input);
const report = JSON.parse((input.endsWith(".gz") ? gunzipSync(bytes) : bytes).toString("utf8"));
const reviewed = new Set((process.env.MOBILE_MUTATION_REVIEW_FILES_JSON ? JSON.parse(process.env.MOBILE_MUTATION_REVIEW_FILES_JSON) : []).flatMap(file => JSON.parse(readFileSync(file, "utf8"))).map(row => row.key));
const excludedFiles = new Set(process.env.MOBILE_MUTATION_EXCLUDE_FILES_JSON ? JSON.parse(process.env.MOBILE_MUTATION_EXCLUDE_FILES_JSON) : []);
const ranges = new Set();
for (const [file, value] of Object.entries(report.files)) {
  if (excludedFiles.has(file)) continue;
  for (const mutant of value.mutants) {
    if (reviewed.has(mutantKey(file, mutant))) continue;
    const watchdog = /^(?:Test|Hook) timed out in \d+ms\./m.test(mutant.statusReason ?? "");
    if (mutant.status === "Killed" && !watchdog && mutant.testsCompleted !== 0) continue;
    const { start, end } = mutant.location;
    ranges.add(`${file}:${start.line}:${start.column - 1}-${end.line}:${end.column - 1}`);
  }
}
if (!ranges.size) throw new Error("No unresolved mutant ranges");
console.log(`Replaying ${ranges.size} source ranges; enclosing and overlapping operators remain enumerable in the resulting report.`);
const runner = resolve(dirname(fileURLToPath(import.meta.url)), "run_frontend_mutation.mjs");
const result = spawnSync(process.execPath, [runner, "--mutate", [...ranges].join(","), "--reporters", "json,progress,mutation-events", "--concurrency", workers, "--timeoutMS", timeout], {
  cwd: resolve(dirname(runner), ".."), stdio: "inherit", env: { ...process.env, MOBILE_MUTATION_REPORT_DIR: output, MOBILE_MUTATION_TEST_FILES_JSON: selectors },
});
process.exit(result.status ?? 1);
