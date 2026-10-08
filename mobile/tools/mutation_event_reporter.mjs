import { appendFileSync, writeFileSync } from "node:fs";
import { relative } from "node:path";
import { declareClassPlugin, PluginKind } from "@stryker-mutator/api/plugin";

class MutationEventReporter {
  onDryRunCompleted(event) {
    if (process.env.MOBILE_MUTATION_EVENT_FILE) writeFileSync(process.env.MOBILE_MUTATION_EVENT_FILE.replace(/\.jsonl$/, ".dry-run.json"), JSON.stringify(event));
  }
  onMutantTested(mutant) {
    if (process.env.MOBILE_MUTATION_EVENT_FILE) appendFileSync(process.env.MOBILE_MUTATION_EVENT_FILE, JSON.stringify({ ...mutant, fileName: relative(process.cwd(), mutant.fileName) }) + "\n");
  }
}
export const strykerPlugins = [declareClassPlugin(PluginKind.Reporter, "mutation-events", MutationEventReporter)];
