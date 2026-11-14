#!/usr/bin/env node
/** Ordinary owned Node provider-refusal test; no automatic mutation credit. */
import {getFips} from 'node:crypto';
import {existsSync,mkdtempSync,readFileSync,realpathSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {cleanEnvironment,runOwned} from './run-native-gc.mjs';
import {hashFile,hashObject,productInputs,recheckFiles,runtimeInventory} from './native-gc-support.mjs';

const require=(value,message)=>{if(!value)throw Error('SetupError: native provider fault command: '+message);};
const empty=value=>value===undefined||value===null||value===''||(Array.isArray(value)&&value.length===0);
export const BODY='preserves the genuine native HKDF failure explanation and current account retry';
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
    check(resolve(suite.name??'')===resolve(root,'tests/accountSecurityHkdfFailure.fault.tsx'),'unselected suite');
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
  require(witness?.stage==='passed'&&witness.nodeVersion===nodeVersion&&/^v22\./.test(nodeVersion),'actual finite Node22 body did not pass');
  require(witness.startingFips===0&&witness.activatedFips===true&&witness.restoredFips===true&&witness.fipsBeforeAssertion===0&&witness.fipsBeforeCleanup===0&&witness.finalFips===0,'native profile not restored before assertion/cleanup');
  require(witness.nativeAesVerified===true&&witness.nativeRefusals===1&&witness.helperRefusals===1&&witness.originalProducerPromisesForwardedUnchanged===true,'actual original AES/HKDF producer census missing');
  require(witness.nativeFailure?.name==='OperationError'&&witness.nativeFailure.fipsAtRefusal===1&&typeof witness.nativeFailure.message==='string'&&witness.nativeFailure.message.length>0&&witness.nativeFailure.stack.includes('node:internal/crypto/hkdf'),'native original HKDF refusal absent');
  const order=['original-AES-open-Promise-fulfilled','native-FIPS-enabled-before-public-caller-HKDF','original-native-HKDF-Promise-rejected','original-public-HKDF-helper-Promise-rejected','native-profile-restored'];
  require(Array.isArray(witness.events)&&order.every((name,index)=>{const at=witness.events.findIndex(event=>event.event===name);return at>=0&&(index===0||at>witness.events.findIndex(event=>event.event===order[index-1]));}),'native producer/profile order witness absent');
  require(witness.publicProducer?.complete===true&&Object.values(witness.publicProducer).every(value=>value===true)&&witness.currentPublicRetryAvailable===true&&witness.cleanupCompleted===true,'actual authenticated public/error/retry/cleanup completion absent');
  return{passed:true,actualNativeRefusalAndPublicRetryQualified:true,verifiedRuntimeKillCredit:0};
}
export async function main(){
  require(process.argv.length===3||process.argv.length===5&&process.argv[3]==='--modules','usage: node tools/run-native-provider-fault.mjs hkdf [--modules /actual/node_modules]');
  require(process.argv[2]==='hkdf'&&/^v22\./.test(process.version),'explicit Node22/hkdf mode required');
  const root=fileURLToPath(new URL('..',import.meta.url)),runtime=runtimeInventory(process.argv[4]?resolve(process.argv[4]):join(root,'node_modules'));
  require(realpathSync(join(root,'node_modules'))===runtime.modules,'actual test imports resolve to another provider');
  const config=join(root,'vitest.native-provider-fault.config.ts'),actor=join(root,'tests/accountSecurityHkdfFailure.fault.tsx');
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
  const directory=mkdtempSync(join(tmpdir(),'mindpattern-portal-native-hkdf-fault-')),rawPath=join(directory,'vitest.json'),witnessPath=join(directory,'resource-receipt.json');
  const env=cleanEnvironment(process.env);env.FRONTEND_NATIVE_FAULT_CACHE_DIR=join(directory,'private-cache');env.NATIVE_HKDF_FAULT_RECEIPT=witnessPath;
  const argv=[process.execPath,join(runtime.modules,'vitest/vitest.mjs'),'run','--config','vitest.native-provider-fault.config.ts','--pool=forks','--maxWorkers=1','--coverage.enabled=false','--reporter=json','--outputFile',rawPath];
  const controller=new AbortController(),interrupt=()=>controller.abort();process.on('SIGINT',interrupt);process.on('SIGTERM',interrupt);
  let step;try{step=await runOwned(argv,{cwd:root,env,signal:controller.signal});}finally{process.removeListener('SIGINT',interrupt);process.removeListener('SIGTERM',interrupt);}
  let raw={},witness={},rawSha256,witnessSha256,reportFault,witnessValidation,witnessFault,custodyFault;
  try{require(existsSync(rawPath),'actual structured report absent');rawSha256=hashFile(rawPath);raw=JSON.parse(readFileSync(rawPath,'utf8'));}catch(error){reportFault=String(error);}
  try{require(existsSync(witnessPath),'actual actor witness absent');witnessSha256=hashFile(witnessPath);witness=JSON.parse(readFileSync(witnessPath,'utf8'));witnessValidation=validateWitness(witness,process.version);}catch(error){witnessFault=String(error);}
  try{verify();require(rawSha256&&hashFile(rawPath)===rawSha256&&witnessSha256&&hashFile(witnessPath)===witnessSha256,'actual raw/witness bytes changed or absent');}catch(error){custodyFault=String(error);}
  const accounting=account(raw,step,root),passed=!reportFault&&!witnessFault&&!custodyFault&&accounting.passed;
  const receipt={kind:'ordinary-owned-native-provider-refusal-command-v1',mode:'hkdf',passed,node,inputHashes,runtimeBinding:runtime,
    driverSha256:hashFile(fileURLToPath(import.meta.url)),actorSha256:hashFile(actor),configSha256:hashFile(config),step,
    driverNativeProfileBefore:startingDriverFips,driverNativeProfileAfter:getFips(),inputsPreserved:!custodyFault,custodyFault,accounting,reportFault,witnessFault,witnessValidation,
    structuredReport:{path:rawPath,sha256:rawSha256??null},witnessFile:{path:witnessPath,sha256:witnessSha256??null},
    mutationExecution:false,verifiedRuntimeKillCredit:0,limitations:['Genuine owned Node22/OpenSSL FIPS HKDF refusal after authenticated AES; not a browser/device FIPS availability claim.','Ordinary original provider Promises and actual public form error/retry; no synthetic rejected Promise/error or private React state.','Ordinary provider failures remain unattributed and receive no automatic mutation credit; canonical mutation/runtime phase requires separate independent adjudication.']};
  const path=join(directory,'command-receipt.json');writeFileSync(path,JSON.stringify(receipt,null,2)+'\n');
  process.stdout.write(JSON.stringify({mode:'hkdf',passed,receipt:path,directory})+'\n');process.exitCode=passed?0:1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(error=>{process.stderr.write(String(error)+'\n');process.exitCode=1;});
