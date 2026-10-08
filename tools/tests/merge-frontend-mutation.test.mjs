import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mergeReports } from '../merge-frontend-mutation.mjs';
import { auditReport, mutantKey } from '../audit-frontend-mutation.mjs';
const source='export const enabled = true;\n';
const mutant={id:'0',mutatorName:'BooleanLiteral',replacement:'false',location:{start:{line:1,column:24},end:{line:1,column:28}}};
const sources=new Map([['src/example.ts',source],['src/types.ts','export type Flag = boolean;\n']]);
const enumeration=[{...mutant,fileName:'src/example.ts'}];
const input=(status,extra={})=>({path:status+'.json',sha256:status,evidence:['runner-witness.json'],report:{files:{'src/example.ts':{source,mutants:[{...mutant,status,...extra}]}},testFiles:{'tests/example.test.ts':{tests:[{id:'0',name:'public consumer'}]}}}});
test('unions overlapping operator runs once and preserves every raw observation',()=>{
 const report=mergeReports(sources,[input('Survived'),input('Killed',{killedBy:['0'],coveredBy:['0']})]);
 assert.equal(auditReport(sources,enumeration,report).runtimeKills,1);
 assert.equal(report.files['src/types.ts'].mutants.length,0);
 const p=report.provenance[mutantKey('src/example.ts',mutant)];assert.equal(p.observations.length,2);assert.equal(p.selected.rawStatus,'Killed');
 assert.deepEqual(report.files['src/example.ts'].mutants[0].killedBy,['run0002::0']);
 assert.equal(report.testFiles['run0002/tests/example.test.ts'].tests[0].id,'run0002::0');
});
test('a later watchdog does not displace a behavioral kill',()=>{
 const report=mergeReports(sources,[input('Killed'),input('Killed',{statusReason:'Test timed out in 5000ms.'})]);
 assert.equal(auditReport(sources,enumeration,report).runtimeKills,1);
 assert.equal(report.provenance[mutantKey('src/example.ts',mutant)].observations[1].testTimeoutFailure,true);
});
test('a reached survivor supersedes a watchdog and stays unresolved',()=>{
 const report=mergeReports(sources,[input('Killed',{statusReason:'Hook timed out in 10000ms.'}),input('Survived')]);
 const audit=auditReport(sources,enumeration,report);assert.equal(audit.runtimeKills,0);assert.equal(audit.unresolved,1);assert.equal(audit.counts.Survived,1);
});
test('rejects stale sources by default and makes explicit skips reviewable',()=>{
 const stale=input('Killed');stale.report.files['src/example.ts'].source+='// changed\n';
 assert.throws(()=>mergeReports(sources,[stale]),/Stale source/);
 const report=mergeReports(sources,[stale],{skipStale:true});assert.equal(report.campaign.skippedStaleSources.length,1);
 assert.throws(()=>auditReport(sources,enumeration,report),/enumerated mutants are missing/);
});
test('rejects duplicate operators, unknown statuses and nonexistent file selections',()=>{
 const duplicate=input('Killed');duplicate.report.files['src/example.ts'].mutants.push({...mutant,id:'new',status:'Killed'});
 assert.throws(()=>mergeReports(sources,[duplicate]),/Duplicate operator/);
 assert.throws(()=>mergeReports(sources,[input('Pending')]),/Unknown\/incomplete/);
 assert.throws(()=>mergeReports(sources,[{...input('Killed'),files:['src/missing.ts']}]),/Selected file absent/);
});
test('explicit file selections exclude unrelated stale campaign targets',()=>{
 const selected=input('Killed');selected.files=['src/example.ts'];selected.report.files['src/types.ts']={source:'stale',mutants:[]};
 assert.equal(auditReport(sources,enumeration,mergeReports(sources,[selected])).complete,true);
});
test('a zero-test observation cannot replace an executed consumer observation',()=>{
 const report=mergeReports(sources,[input('Survived',{testsCompleted:1}),input('Killed',{testsCompleted:0})]);
 const audit=auditReport(sources,enumeration,report);
 assert.equal(audit.counts.Survived,1); assert.equal(audit.runtimeKills,0); assert.equal(audit.unresolved,1);
 assert.equal(report.provenance[mutantKey('src/example.ts',mutant)].observations[1].zeroTestsCompleted,true);
});
test('an uncovered replay cannot hide an earlier execution timeout',()=>{
 const report=mergeReports(sources,[input('Timeout'),input('NoCoverage')]);
 const audit=auditReport(sources,enumeration,report);
 assert.equal(audit.counts.Timeout,1); assert.equal(audit.counts.NoCoverage,0); assert.equal(audit.unresolved,1);
});
const rejection={key:mutantKey('src/example.ts',mutant),reason:'The identical unrelated snapshot failure also occurred on pristine source.',evidence:['pristine-repetition.json','oracle-diagnosis.md']};
test('a rejected fixture kill preserves its raw provenance and cannot displace a valid survivor',()=>{
 const bad={...input('Killed',{killedBy:['0']}),rejectObservations:[rejection]};
 for(const inputs of [[input('Survived'),bad],[bad,input('Survived')]]){
  const report=mergeReports(sources,inputs);const audit=auditReport(sources,enumeration,report);
  assert.equal(audit.runtimeKills,0);assert.equal(audit.counts.Survived,1);assert.equal(audit.unresolved,1);
  const observations=report.provenance[rejection.key].observations;
  assert.equal(observations.find(row=>row.rejection).rawStatus,'Killed');
  assert.deepEqual(observations.find(row=>row.rejection).rejection,rejection);
 }
});
test('a rejected-only observation retains its operator and requires a trustworthy replay',()=>{
 const report=mergeReports(sources,[{...input('Killed'),rejectObservations:[rejection]}]);
 const audit=auditReport(sources,enumeration,report);assert.equal(audit.total,1);assert.equal(audit.runtimeKills,0);assert.equal(audit.counts.Ignored,1);assert.equal(audit.unresolved,1);
});
test('observation rejection needs exact matched identity and review evidence',()=>{
 assert.throws(()=>mergeReports(sources,[{...input('Killed'),rejectObservations:[{...rejection,key:'missing'}]}]),/Unmatched observation/);
 assert.throws(()=>mergeReports(sources,[{...input('Killed'),rejectObservations:[{...rejection,evidence:[]}]}]),/Incomplete/);
 assert.throws(()=>mergeReports(sources,[{...input('Killed'),rejectObservations:[rejection,rejection]}]),/duplicate/);
});
