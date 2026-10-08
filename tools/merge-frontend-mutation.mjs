// Combine explicitly reviewed campaign inputs by exact current-source operator
// identity. This preserves raw observations and never credits a test watchdog
// over a later behavioral result. Runner/oracle validity needs separate review.
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync, gunzipSync } from 'node:zlib';
import { inventory, mutantKey } from './audit-frontend-mutation.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const timedOut = mutant => mutant.status === 'Killed' && /^(?:Test|Hook) timed out in \d+ms\./m.test(mutant.statusReason ?? '');
const emptyRun = mutant => ['Killed','Survived'].includes(mutant.status) && mutant.testsCompleted === 0;
const validStatuses = new Set(['Killed','Survived','NoCoverage','Timeout','CompileError','RuntimeError','Ignored']);
const rank = mutant => emptyRun(mutant) && !timedOut(mutant) ? 0 : mutant.status === 'Killed' && !timedOut(mutant) ? 6
  : mutant.status === 'Survived' ? 5
  : timedOut(mutant) || mutant.status === 'Timeout' ? 4
  : mutant.status === 'NoCoverage' ? 3
  : mutant.status === 'CompileError' ? 2 : 1;

export function mergeReports(sources, inputs, { skipStale = false } = {}) {
  const byFile = new Map();
  const testFiles = {};
  const provenance = {};
  const skipped = [];
  const manifests = [];
  for (const [index, input] of inputs.entries()) {
    const namespace = `run${String(index + 1).padStart(4,'0')}`;
    const report = input.report;
    if (!report?.files || Array.isArray(report.files)) throw new Error(`Missing report files: ${input.path}`);
    const selectedFiles = input.files ? new Set(input.files) : null;
    if (selectedFiles) for (const file of selectedFiles) if (!Object.hasOwn(report.files,file)) throw new Error(`Selected file absent: ${input.path} ${file}`);
    if (input.rejectObservations && !Array.isArray(input.rejectObservations)) throw new Error(`Invalid observation rejections: ${input.path}`);
    const rejections = new Map();
    for (const rejection of input.rejectObservations ?? []) {
      if (!rejection?.key || !rejection.reason?.trim() || !Array.isArray(rejection.evidence) || !rejection.evidence.length || rejections.has(rejection.key)) {
        throw new Error(`Incomplete/duplicate observation rejection: ${input.path}`);
      }
      rejections.set(rejection.key, rejection);
    }
    manifests.push({ path: input.path, sha256: input.sha256, ...(input.files ? { files: input.files } : {}), evidence: input.evidence ?? [],
      ...(input.rejectObservations ? { rejectObservations: input.rejectObservations } : {}) });
    for (const [file, data] of Object.entries(report.testFiles ?? {})) {
      testFiles[`${namespace}/${file}`] = { ...data, tests: (data.tests ?? []).map(test => ({ ...test, id: `${namespace}::${test.id}` })) };
    }
    for (const [file, data] of Object.entries(report.files)) {
      if (selectedFiles && !selectedFiles.has(file)) continue;
      if (!sources.has(file)) throw new Error(`Out-of-scope source: ${input.path} ${file}`);
      if (data.source !== sources.get(file)) {
        if (!skipStale) throw new Error(`Stale source: ${input.path} ${file}`);
        skipped.push({ path: input.path, file, reportSourceSha256: hash(data.source ?? ''), currentSourceSha256: hash(sources.get(file)) });
        continue;
      }
      if (!Array.isArray(data.mutants)) throw new Error(`Missing mutants: ${input.path} ${file}`);
      const operators = byFile.get(file) ?? new Map(); byFile.set(file,operators);
      const seen = new Set();
      for (const mutant of data.mutants) {
        if (!validStatuses.has(mutant.status)) throw new Error(`Unknown/incomplete status: ${input.path} ${file} ${mutant.id}`);
        const key = mutantKey(file,mutant);
        if (seen.has(key)) throw new Error(`Duplicate operator in input: ${input.path} ${file} ${mutant.id}`);
        seen.add(key);
        const observation = { input: namespace, path: input.path, sha256: input.sha256, file, rawId: mutant.id, rawStatus: mutant.status,
          ...(timedOut(mutant) ? { testTimeoutFailure: true } : {}), evidence: input.evidence ?? [] };
        if (emptyRun(mutant)) observation.zeroTestsCompleted = true;
        const rejection = rejections.get(key);
        if (rejection) {
          observation.rejection = rejection;
          rejections.delete(key);
        }
        const row = operators.get(key) ?? { observations: [] };
        row.observations.push(observation);
        // At equal evidence strength, retain the later selected consumer run.
        if (rejection && !row.mutant) {
          // Retain the operator inventory, but require an executed trustworthy
          // replay when every observation has been rejected by oracle review.
          row.mutant = { ...mutant, status: 'Ignored', statusReason: `Rejected oracle observation: ${rejection.reason}`, coveredBy: [], killedBy: [] };
          row.selected = observation;
          row.rejectedOnly = true;
        } else if (!rejection && (!row.mutant || row.rejectedOnly || rank(mutant) >= rank(row.mutant))) {
          row.mutant = { ...mutant,
            ...(mutant.coveredBy ? { coveredBy: mutant.coveredBy.map(id => `${namespace}::${id}`) } : {}),
            ...(mutant.killedBy ? { killedBy: mutant.killedBy.map(id => `${namespace}::${id}`) } : {}) };
          row.selected = observation;
          row.rejectedOnly = false;
        }
        operators.set(key,row);
      }
    }
    if (rejections.size) throw new Error(`Unmatched observation rejections: ${input.path} ${rejections.size}`);
  }
  const files = {};
  for (const [file,source] of sources) {
    const entries = [...(byFile.get(file) ?? [])].sort(([a],[b]) => a.localeCompare(b));
    files[file] = { source, mutants: entries.map(([key,row],index) => {
      provenance[key] = { selected: row.selected, observations: row.observations };
      return { ...row.mutant, id: String(index) };
    }) };
  }
  return { schemaVersion: '1.0', files, testFiles, thresholds: { high: 100, low: 0 },
    campaign: { note: 'Exact-source operator union; raw inputs and selected per-operator provenance retained. Requires independent inventory and residual/oracle review.', inputs: manifests, skippedStaleSources: skipped },
    provenance };
}

async function jsonFile(path) {
  const bytes = await readFile(path);
  return { bytes, value: JSON.parse((path.endsWith('.gz') ? gunzipSync(bytes) : bytes).toString('utf8')) };
}

async function main() {
  const [packagePath, manifestPath, outputPath, ...options] = process.argv.slice(2);
  if (!packagePath || !manifestPath || !outputPath || options.some(option => option !== '--skip-stale') || options.length > 1) throw new Error('usage: node tools/merge-frontend-mutation.mjs PACKAGE INPUT_MANIFEST OUTPUT[.gz] [--skip-stale]');
  const manifest = (await jsonFile(manifestPath)).value;
  if (!Array.isArray(manifest)) throw new Error('Input manifest must be an array of paths or {path, files?, evidence?, rejectObservations?} records');
  const inputs = [];
  for (const entry of manifest) {
    const input = typeof entry === 'string' ? { path: entry } : entry;
    if (!input?.path || (input.files && !Array.isArray(input.files))) throw new Error('Invalid manifest entry');
    const { bytes,value } = await jsonFile(input.path);
    inputs.push({ ...input, sha256: hash(bytes), report: value });
  }
  const report = mergeReports(await inventory(resolve(packagePath)),inputs,{ skipStale: options.includes('--skip-stale') });
  const serialized = Buffer.from(JSON.stringify(report)+'\n');
  await writeFile(outputPath,outputPath.endsWith('.gz') ? gzipSync(serialized) : serialized);
  console.log(JSON.stringify({ files: Object.keys(report.files).length, operators: Object.values(report.files).reduce((sum,file)=>sum+file.mutants.length,0), skippedStaleSources: report.campaign.skippedStaleSources.length, output: outputPath }));
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(error => { console.error(`Invalid merge evidence: ${error.message}`); process.exitCode = 2; });
