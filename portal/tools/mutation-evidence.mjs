import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { runtimeKill } from '../../tools/mutation-observation.mjs';

const digest = contents => createHash('sha256').update(contents).digest('hex');

export function residualMutationRanges(file, mutants) {
  return [...new Set(mutants.filter(mutant => mutant.status !== 'Killed' || !runtimeKill(mutant)).map(mutant => {
    const { start, end } = mutant.location;
    return `${file}:${start.line}:${start.column - 1}-${end.line}:${end.column - 1}`;
  }))];
}

export async function digestTree(path, prefix = '') {
  const files = {};
  for (const entry of (await readdir(path, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) Object.assign(files, await digestTree(join(path, entry.name), relative));
    else if (entry.isFile()) files[relative] = digest(await readFile(join(path, entry.name)));
  }
  return files;
}

export async function captureInputs(packageRoot) {
  const inputs = {};
  for (const [name, path] of Object.entries({ source: 'src', tests: 'tests', tools: 'tools', public: 'public', data: 'data' })) {
    try {
      inputs[name] = await digestTree(join(packageRoot, path));
    } catch (error) {
      // The optional local data directory can be absent from a source-only
      // snapshot. Preserve absence so creating data during a run is detected.
      if (name === 'data' && error.code === 'ENOENT') inputs[name] = null;
      else throw error;
    }
  }
  inputs.shared = await digestTree(join(dirname(packageRoot), 'shared'));
  inputs.nginx = digest(await readFile(join(dirname(packageRoot), 'deploy/nginx/mindpattern.conf.example')));
  inputs.config = {};
  for (const name of ['package.json', 'package-lock.json', 'vite.config.ts', 'tsconfig.json', 'index.html', 'stryker.config.json']) {
    inputs.config[name] = digest(await readFile(join(packageRoot, name)));
  }
  return inputs;
}

export async function verifyInputs(packageRoot, expected, phase) {
  const actual = await captureInputs(packageRoot);
  const changed = Object.keys(expected).filter(name => JSON.stringify(expected[name]) !== JSON.stringify(actual[name]));
  if (changed.length) throw new Error(`${phase}: frozen inputs changed in ${changed.join(', ')}. Workspace retained at ${packageRoot}.`);
}

export function validateReport(report, expectedSources, exitCode, threshold) {
  if (JSON.stringify(Object.keys(report.files ?? {}).sort()) !== JSON.stringify(Object.keys(expectedSources).sort())) throw new Error('Mutation report omitted selected sources or contains unexpected files.');
  const counts = {};
  const terminal = new Set(['Killed', 'Timeout', 'Survived', 'NoCoverage', 'CompileError', 'RuntimeError', 'Ignored']);
  for (const [file, expectedHash] of Object.entries(expectedSources)) {
    const result = report.files[file];
    if (digest(result.source) !== expectedHash) throw new Error(`Mutation report source differs from frozen input: ${file}`);
    if (!result.mutants?.length || result.mutants.some(mutant => !terminal.has(mutant.status))) throw new Error(`Mutation report has no operators or unfinished/unknown statuses: ${file}`);
    for (const mutant of result.mutants) counts[mutant.status] = (counts[mutant.status] ?? 0) + 1;
  }
  const scored = ['Killed', 'Timeout', 'Survived', 'NoCoverage'].reduce((sum, status) => sum + (counts[status] ?? 0), 0);
  const rawMutationScore = scored ? ((counts.Killed ?? 0) + (counts.Timeout ?? 0)) / scored * 100 : 100;
  const expectedExit = rawMutationScore < threshold ? 1 : 0;
  if (exitCode !== expectedExit) throw new Error(`Mutation runner exit ${exitCode} does not match completed report score exit ${expectedExit}.`);
  return { counts, total: Object.values(counts).reduce((sum, count) => sum + count, 0), rawMutationScore, expectedExit };
}
