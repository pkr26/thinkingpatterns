#!/usr/bin/env node
// Digest a Stryker mutation.json into per-file tables + a triage-ready
// survivor listing (original -> replacement extracted from the file source).
// Usage: node analyze_mutation.js <mutation.json> [--file <substr>] [--status Survived,NoCoverage] [--top N]
import { readFileSync } from 'node:fs';

const args = process.argv.slice(2);
const reportPath = args.shift();
const filters = { file: null, status: ['Survived', 'NoCoverage'], top: 40 };
while (args.length) {
  const a = args.shift();
  if (a === '--file') filters.file = args.shift();
  else if (a === '--status') filters.status = args.shift().split(',');
  else if (a === '--top') filters.top = parseInt(args.shift(), 10);
}
if (!reportPath) { console.error('usage: analyze_mutation.js <mutation.json>'); process.exit(2); }

const r = JSON.parse(readFileSync(reportPath, 'utf8'));
const files = Object.entries(r.files ?? {}).map(([abs, f]) => {
  const rel = abs.replace(/^.*\/(portal|mobile)\//, '$1/');
  const counts = {};
  for (const m of f.mutants) counts[m.status] = (counts[m.status] ?? 0) + 1;
  const killed = (counts.Killed ?? 0) + (counts.Timeout ?? 0);
  const covered = killed + (counts.Survived ?? 0) + (counts.NoCoverage ?? 0) + (counts.RuntimeError ?? 0);
  return { rel, abs, counts, killed, covered, mutants: f.mutants, source: f.source };
});
files.sort((a, b) => (b.counts.Survived ?? 0) - (a.counts.Survived ?? 0));

let K = 0, S = 0, N = 0, T = 0, E = 0;
for (const f of files) { K += f.killed; S += f.counts.Survived ?? 0; N += f.counts.NoCoverage ?? 0; T += f.counts.Timeout ?? 0; E += f.counts.RuntimeError ?? 0; }
const cov = K + S + N + E;
console.log(`AGGREGATE: ${K + S + N + E} mutants | killed ${K} | timeout ${T} | survived ${S} | no-coverage ${N} | errors ${E} | score ${cov ? ((K / cov) * 100).toFixed(2) : 'n/a'}%\n`);
console.log('PER FILE (sorted by survivors):');
console.log('  survivors | killed | score | file');
for (const f of files) {
  const score = f.covered ? ((f.killed / f.covered) * 100).toFixed(1) : 'n/a';
  console.log(`  ${(f.counts.Survived ?? 0) + (f.counts.NoCoverage ?? 0)}`.padStart(9) + ` | ${String(f.killed).padStart(6)} | ${String(score).padStart(5)} | ${f.rel}`);
}

console.log(`\nSURVIVORS (${filters.status.join(',')}${filters.file ? `, file~${filters.file}` : ''}), top ${filters.top} per line-group:`);
for (const f of files) {
  if (filters.file && !f.rel.includes(filters.file)) continue;
  const surv = f.mutants.filter(m => filters.status.includes(m.status));
  if (!surv.length) continue;
  const lines = (f.source ?? '').split('\n');
  console.log(`\n## ${f.rel} — ${surv.length} surviving`);
  const byLoc = new Map();
  for (const m of surv) {
    const key = m.location.start.line;
    if (!byLoc.has(key)) byLoc.set(key, []);
    byLoc.get(key).push(m);
  }
  let shown = 0;
  for (const [line, ms] of [...byLoc.entries()].sort((a, b) => a[0] - b[0])) {
    if (shown >= filters.top) { console.log('  ... (more; raise --top)'); break; }
    const src = lines[line - 1]?.trim() ?? '';
    for (const m of ms) {
      const repl = (m.replacement ?? '').replace(/\n/g, '\\n');
      console.log(`  L${line}:${m.location.start.column + 1} [${m.mutatorName}] ${JSON.stringify(src.slice(0, 160))}`);
      console.log(`      -> ${JSON.stringify(repl.slice(0, 160))} ${m.status === 'NoCoverage' ? '(NO-COV)' : ''}`);
      shown++;
      if (shown >= filters.top) break;
    }
  }
}
