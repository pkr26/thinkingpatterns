import assert from 'node:assert/strict';
import test from 'node:test';
import {account,BODY,validateWitness} from './run-native-provider-fault.mjs';

const root='/owned/portal';
const step=()=>({executionStatus:'completed',ownedGroupRetired:true,exitCode:0,timedOut:false,interrupted:false,descendantsOutlivedLeader:false});
const raw=()=>({success:true,numTotalTests:1,numPassedTests:1,numFailedTests:0,numPendingTests:0,numRuntimeErrorTestSuites:0,testResults:[{name:root+'/tests/accountSecurityHkdfFailure.fault.tsx',status:'passed',message:'',assertionResults:[{fullName:BODY,status:'passed',failureMessages:[]}]}]});
const witness=()=>({stage:'passed',nodeVersion:'v22.14.0',startingFips:0,activatedFips:true,restoredFips:true,fipsBeforeAssertion:0,fipsBeforeCleanup:0,finalFips:0,nativeAesVerified:true,nativeRefusals:1,helperRefusals:1,originalProducerPromisesForwardedUnchanged:true,nativeFailure:{name:'OperationError',fipsAtRefusal:1,message:'The operation failed',stack:'OperationError\n at node:internal/crypto/hkdf:159'},events:['original-AES-open-Promise-fulfilled','native-FIPS-enabled-before-public-caller-HKDF','original-native-HKDF-Promise-rejected','original-public-HKDF-helper-Promise-rejected','native-profile-restored'].map(event=>({event})),publicProducer:{complete:true,independent600kPasswordProofs:true,mandatoryMfaAccepted:true,genuineAuthenticatedProfiles:true,sameSessionActive:true},currentPublicRetryAvailable:true,cleanupCompleted:true});

test('completed ordinary command remains zero mutation credit',()=>{
  const result=account(raw(),step(),root);
  assert.equal(result.passed,true);
  assert.equal(result.verifiedRuntimeKillCredit,0);
  assert.equal(validateWitness(witness(),'v22.14.0').verifiedRuntimeKillCredit,0);
});
test('nominal provider success cannot hide missing, unfinished, foreign or outside failures',()=>{
  const cases=[
    report=>{report.numTotalTests=0;report.numPassedTests=0;report.testResults=[];},
    report=>{report.testResults[0].assertionResults[0].status='failed';report.testResults[0].assertionResults[0].failureMessages=['AssertionError: native error lost'];},
    report=>{report.testResults[0].assertionResults[0].fullName='an unrelated passing test';},
    report=>{report.testResults[0].message='beforeAll failed';},
    report=>{report.unhandledErrors=['outside provider failure'];},
    report=>{report.numPendingTests=1;},
  ];
  for(const mutate of cases){const report=raw();mutate(report);assert.equal(account(report,step(),root).passed,false);}
});
test('an owned child deadline, orphan or signal cannot count as passing',()=>{
  for(const field of ['timedOut','interrupted','descendantsOutlivedLeader','spawnError','cleanupError','terminationSignal']){
    const current=step();current[field]=field==='terminationSignal'?'SIGTERM':true;
    assert.equal(account(raw(),current,root).passed,false,field);
  }
});
test('native profile needs genuine original refusal, ordering and restoration before assertions',()=>{
  const cases=[
    value=>{value.nativeFailure.stack='invented rejection';},
    value=>{value.nativeFailure.name='Error';},
    value=>{value.nativeFailure.fipsAtRefusal=0;},
    value=>{value.nativeRefusals=0;},
    value=>{value.originalProducerPromisesForwardedUnchanged=false;},
    value=>{value.fipsBeforeAssertion=1;},
    value=>{value.finalFips=1;},
    value=>{value.events.reverse();},
    value=>{value.publicProducer.independent600kPasswordProofs=false;},
    value=>{value.currentPublicRetryAvailable=false;},
    value=>{value.cleanupCompleted=false;},
  ];
  for(const mutate of cases){const value=witness();mutate(value);assert.throws(()=>validateWitness(value,'v22.14.0'),/SetupError/);}
});
