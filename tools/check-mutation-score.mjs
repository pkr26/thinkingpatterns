#!/usr/bin/env node
// Validate a complete Stryker report and enforce an inclusive minimum.
import { readFileSync } from 'node:fs';

const [reportPath, rawFloor, ...extra] = process.argv.slice(2);
const floor = Number(rawFloor);
if (!reportPath || rawFloor === undefined || !rawFloor.trim() || extra.length || !Number.isFinite(floor) || floor < 0 || floor > 100) {
  console.error('usage: node tools/check-mutation-score.mjs REPORT MINIMUM_0_TO_100');
  process.exit(64);
}
try {
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  if (!report.files || typeof report.files !== 'object' || Array.isArray(report.files)) throw new Error('missing report files');
  const counts = { Killed: 0, Timeout: 0, Survived: 0, NoCoverage: 0, CompileError: 0, RuntimeError: 0, Ignored: 0 };
  for (const [name, file] of Object.entries(report.files)) {
    if (!Array.isArray(file.mutants)) throw new Error(`missing mutants in ${name}`);
    for (const mutant of file.mutants) {
      if (!Object.hasOwn(counts, mutant.status)) throw new Error(`incomplete/unknown mutant status in ${name}: ${mutant.status}`);
      counts[mutant.status]++;
    }
  }
  // Compilation-invalid/explicitly ignored mutants are excluded by Stryker,
  // but a broken runtime cannot be credited as a successful test campaign.
  if (counts.RuntimeError) throw new Error(`${counts.RuntimeError} runtime-error mutants require investigation`);
  const covered = counts.Killed + counts.Timeout + counts.Survived + counts.NoCoverage;
  if (!covered) throw new Error('report has no scoreable mutants');
  const score = 100 * (counts.Killed + counts.Timeout) / covered;
  console.log(`mutation score: ${score.toFixed(4)}%; minimum: ${floor}%`);
  console.log(JSON.stringify(counts));
  if (score < floor) {
    console.error(`mutation score is below ${floor}%`);
    process.exitCode = 1;
  }
} catch (error) {
  console.error(`invalid mutation evidence: ${error.message}`);
  process.exitCode = 2;
}
