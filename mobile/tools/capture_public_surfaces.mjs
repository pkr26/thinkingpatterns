import { mkdirSync, readFileSync, readdirSync, renameSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const mobile = resolve(dirname(fileURLToPath(import.meta.url)), "..");
if (process.env.MOBILE_MUTATION_EVENT_FILE) throw new Error("UI oracle capture is allowed only on a pristine control run");
const result = spawnSync(process.execPath, [join(mobile, "node_modules/vitest/vitest.mjs"), "run", "--coverage.enabled=false"], {
  cwd: mobile, stdio: "inherit", env: { ...process.env, MOBILE_UPDATE_PUBLIC_SURFACES: "1" },
});
if (result.status !== 0) process.exit(result.status ?? 1);
function walk(directory) { return readdirSync(directory, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? walk(join(directory, entry.name)) : [join(directory, entry.name)]); }
// Preserve the reviewed initial Vitest capture as ignored evidence; normal
// tests consume only exact decoded compressed public-output expectations.
for (const file of walk(join(mobile, "tests")).filter(file => file.endsWith(".snap"))) {
  if (!readFileSync(file, "utf8").includes(" > rendered native surface ")) continue;
  const archive = join(mobile, "reports/mutation-2026-10-05/ui-snapshots-original", relative(join(mobile, "tests"), file));
  mkdirSync(dirname(archive), { recursive: true });
  renameSync(file, archive);
}
