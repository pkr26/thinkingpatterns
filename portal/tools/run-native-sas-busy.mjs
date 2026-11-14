#!/usr/bin/env node
/** Ordinary owned native busy-provider command; no automatic mutation credit. */
import {getFips} from 'node:crypto';
import {existsSync,mkdtempSync,readFileSync,realpathSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {cleanEnvironment,runOwned} from './run-native-gc.mjs';
import {hashFile,hashObject,productInputs,recheckFiles,runtimeInventory} from './native-gc-support.mjs';

const require=(value,message)=>{if(!value)throw Error('SetupError: native SAS busy command: '+message);};
const empty=value=>value===undefined||value===null||value===''||(Array.isArray(value)&&value.length===0);
export const BODY='keeps a current SAS comparison unverified while its own native digest is pending';
export function account(raw,step,root){
  const faults=[],identities=[];
  const check=(value,message)=>{if(!value)faults.push(message);};
  check(step.executionStatus==='completed'&&step.ownedGroupRetired===true&&step.exitCode===0&&!step.timedOut&&!step.interrupted&&!step.descendantsOutlivedLeader&&!step.spawnError&&!step.cleanupError&&!step.terminationSignal,'ordinary provider exit/owned-group/deadline failure');
  check(raw?.success===true,'ordinary provider did not pass');
  for(const name of ['errors','unhandledErrors','unhandledRejections'])check(empty(raw?.[name]),'outside provider errors: '+name);
  for(const name of ['numFailedTests','numRuntimeErrorTestSuites','numPendingTests','numTodoTests'])check(raw?.[name]===undefined||raw[name]===0,'unfinished/failed census: '+name);
  const suites=raw?.testResults;
  check(Array.isArray(suites)&&suites.length===1,'exact one collected suite required');
  for(const suite of Array.isArray(suites)?suites:[]){
    check(resolve(suite.name??'')===resolve(root,'tests/sasFingerprintPending.busy.tsx'),'unselected suite');
    check(suite.status==='passed','suite did not pass');
    for(const name of ['message','error','errors','failureMessage','failureMessages','testExecError'])check(empty(suite[name]),'suite/setup/cleanup error: '+name);
    check(Array.isArray(suite.assertionResults)&&suite.assertionResults.length===1,'exact one actual body required');
    for(const test of suite.assertionResults??[]){
      identities.push({file:suite.name,fullName:test.fullName,status:test.status});
      check(test.fullName===BODY&&test.status==='passed','actual body did not complete/pass');
      for(const name of ['failureMessages','errors','error','failureMessage','testExecError'])check(empty(test[name]),'ordinary body failure: '+name);
    }
  }
  check(raw?.numTotalTests===1&&raw?.numPassedTests===1,'actual body total/passed census mismatch');
  return{passed:faults.length===0,faults,identities,ordinaryTestEvidenceOnly:true,failurePhaseNotInferredFromSerializedMessage:true,verifiedRuntimeKillCredit:0};
}
export function validateWitness(witness,nodeVersion){
  require(witness?.stage==='passed'&&witness.nodeVersion===nodeVersion&&/^v22\./.test(nodeVersion)&&witness.workerPool==='1'&&witness.actualNativeMainThread===true&&Number.isSafeInteger(witness.actorPid)&&witness.actorPid!==process.pid,'actual finite owned fork Node22/UV1 body did not pass');
  require(witness.startingFips===0&&witness.finalFips===0,'unrequested native provider mode change');
  require(witness.originalProductionPromisesForwardedUnchanged===true&&witness.originalSasPromiseCount===2&&witness.originalFingerprintPromiseCount===2,'original native/public Promise census missing');
  require(witness.beforeAssertion?.oldFingerprintSettled===true&&witness.beforeAssertion?.currentFingerprintPending===true&&witness.beforeAssertion?.betweenNativeBusyTaskPending===true&&JSON.stringify(witness.beforeAssertion?.currentSas)==='["654321"]','actual old/current native queue and current SAS witness absent');
  require(witness.correctNativeDigestPositiveControls===true&&witness.allOwnedOriginalProducersFulfilled===true&&witness.cleanupCompleted===true,'native digest positive/cleanup control incomplete');
  require(Array.isArray(witness.finiteNativeBusyTasks)&&witness.finiteNativeBusyTasks.length===2&&witness.finiteNativeBusyTasks.every(row=>row.settled===true&&row.zeroized===true),'finite actual PBKDF2 jobs did not drain and zeroize');
  const inputs=witness.nativeInputTasks;
  require(Array.isArray(inputs)&&inputs.length===4&&inputs.every(row=>row.currentDom===true&&row.enabled===true&&row.separateNativeTask===true)&&JSON.stringify(inputs.map(row=>row.label))===JSON.stringify(['Generate pairing code','Show verification code','Generate pairing code','Show verification code']),'separate actual current-DOM native input task census differs');
  const order=['original-native-fingerprint-0-fulfilled','current-warning-assertion-ready','original-native-fingerprint-1-fulfilled'];
  require(Array.isArray(witness.events)&&order.every((name,index)=>{const at=witness.events.findIndex(event=>event.event===name);return at>=0&&(index===0||at>witness.events.findIndex(event=>event.event===order[index-1]));}),'original native digest/assertion order absent');
  require(witness.publicProducer?.complete===true&&Object.values(witness.publicProducer).every(value=>value===true),'authenticated actual public producer incomplete');
  return{passed:true,actualNativeBusyPendingComparisonQualified:true,verifiedRuntimeKillCredit:0};
}
export async function main(){
  require(process.argv.length===3||process.argv.length===5&&process.argv[3]==='--modules','usage: node tools/run-native-sas-busy.mjs fingerprint [--modules /actual/node_modules]');
  require(process.argv[2]==='fingerprint'&&/^v22\./.test(process.version),'explicit Node22/fingerprint mode required');
  const root=fileURLToPath(new URL('..',import.meta.url)),runtime=runtimeInventory(process.argv[4]?resolve(process.argv[4]):join(root,'node_modules'));
  require(realpathSync(join(root,'node_modules'))===runtime.modules,'actual test imports resolve to another provider');
  const config=join(root,'vitest.sas-busy.config.ts'),actor=join(root,'tests/sasFingerprintPending.busy.tsx');
  require(existsSync(config)&&existsSync(actor),'promoted config/actual actor absent');
  const support=[fileURLToPath(import.meta.url),fileURLToPath(new URL('./run-native-gc.mjs',import.meta.url)),fileURLToPath(new URL('./native-gc-support.mjs',import.meta.url))];
  const inputs=()=>({...productInputs(root),...Object.fromEntries(support.map(path=>[path,hashFile(path)]))});
  const inputHashes=inputs(),node={path:process.execPath,version:process.version,sha256:hashFile(process.execPath)},startingDriverFips=getFips();
  require(startingDriverFips===0,'driver must start outside native FIPS profile');
  const verify=()=>{
    require(hashObject(inputs())===hashObject(inputHashes),'whole product/test/config/shared input inventory changed');recheckFiles(inputHashes);
    require(realpathSync(join(root,'node_modules'))===runtime.modules&&runtimeInventory(runtime.modules).digest===runtime.digest,'provider binding/inventory changed');
    recheckFiles(Object.fromEntries(Object.entries(runtime.wholeProviderCompilerAndConsumerHashes).map(([name,sha])=>[join(runtime.modules,name),sha])));
    require(hashFile(node.path)===node.sha256&&getFips()===startingDriverFips,'driver Node executable/native profile changed');
  };
  verify();
  const directory=mkdtempSync(join(tmpdir(),'mindpattern-portal-native-sas-busy-')),rawPath=join(directory,'vitest.json'),witnessPath=join(directory,'provider-receipt.json');
  const env=cleanEnvironment(process.env);env.FRONTEND_NATIVE_SAS_BUSY_CACHE_DIR=join(directory,'private-cache');env.FRONTEND_NATIVE_SAS_BUSY_RECEIPT=witnessPath;env.UV_THREADPOOL_SIZE='1';
  const argv=[process.execPath,join(runtime.modules,'vitest/vitest.mjs'),'run','--config','vitest.sas-busy.config.ts','--pool=forks','--maxWorkers=1','--coverage.enabled=false','--reporter=json','--outputFile',rawPath];
  const controller=new AbortController(),interrupt=()=>controller.abort();process.on('SIGINT',interrupt);process.on('SIGTERM',interrupt);
  let step;try{const owned=await runOwned(argv,{cwd:root,env,signal:controller.signal});step={...owned,evidenceClass:'ordinary-native-node-busy-provider-command',ownershipHelperEvidenceClass:owned.evidenceClass};}finally{process.removeListener('SIGINT',interrupt);process.removeListener('SIGTERM',interrupt);}
  let raw={},witness={},rawSha256,witnessSha256,reportFault,witnessValidation,witnessFault,custodyFault;
  try{require(existsSync(rawPath),'actual structured report absent');rawSha256=hashFile(rawPath);raw=JSON.parse(readFileSync(rawPath,'utf8'));}catch(error){reportFault=String(error);}
  try{require(existsSync(witnessPath),'actual actor witness absent');witnessSha256=hashFile(witnessPath);witness=JSON.parse(readFileSync(witnessPath,'utf8'));witnessValidation=validateWitness(witness,process.version);}catch(error){witnessFault=String(error);}
  try{verify();require(rawSha256&&hashFile(rawPath)===rawSha256&&witnessSha256&&hashFile(witnessPath)===witnessSha256,'actual raw/witness bytes changed or absent');}catch(error){custodyFault=String(error);}
  const accounting=account(raw,step,root),passed=!reportFault&&!witnessFault&&!custodyFault&&accounting.passed;
  const receipt={kind:'ordinary-owned-native-busy-provider-command-v1',mode:'fingerprint',passed,node,inputHashes,runtimeBinding:runtime,
    driverSha256:hashFile(fileURLToPath(import.meta.url)),actorSha256:hashFile(actor),configSha256:hashFile(config),step,
    driverNativeProfileBefore:startingDriverFips,driverNativeProfileAfter:getFips(),inputsPreserved:!custodyFault,custodyFault,accounting,reportFault,witnessFault,witnessValidation,
    structuredReport:{path:rawPath,sha256:rawSha256??null},witnessFile:{path:witnessPath,sha256:witnessSha256??null},
    mutationExecution:false,verifiedRuntimeKillCredit:0,limitations:['Explicit owned Node22/UV1 busy native provider and actual DOM input Tasks; not a physical-browser timing claim.','Original native SHA256 and production public Promises are unchanged; actual finite PBKDF2 jobs create contention and are fully drained.','All ordinary failures remain unattributed and receive no automatic mutation credit; exact canonical mutation/runtime phase requires separate independent adjudication.']};
  const path=join(directory,'command-receipt.json');writeFileSync(path,JSON.stringify(receipt,null,2)+'\n');
  process.stdout.write(JSON.stringify({mode:'fingerprint',passed,receipt:path,directory})+'\n');process.exitCode=passed?0:1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(error=>{process.stderr.write(String(error)+'\n');process.exitCode=1;});
