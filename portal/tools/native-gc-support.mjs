/** Portable ordinary-test accounting. It never assigns mutation kill credit. */
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

const require = (ok, message) => { if (!ok) throw new Error('SetupError: native GC accounting: ' + message); };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const natural = (value, minimum = 0) => Number.isSafeInteger(value) && value >= minimum;
const empty = value => value === undefined || value === null || value === '' || (Array.isArray(value) && value.length === 0);
export const hashFile = path => createHash('sha256').update(readFileSync(path)).digest('hex');
const canonical = value => Array.isArray(value) ? value.map(canonical) : object(value)
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
export const hashObject = value => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');

export const BODY_NAMES = Object.freeze({
  'settled-slot': ["a retiring account cannot erase the replacement registration's unseen memo under FIFO native storage", 'releases fulfilled public slot-write Promise allocations after the real UI rotation and erasure flow'],
  'local-rekey-tail': ['completed public rotations release settled journal factory Promise allocations across successor generations'],
  'private-key': ['collects the imported nonextractable private key after actual portal unmount'],
  'draft-tail': ['releases fulfilled native draft-write Promises after legitimate clinician chart navigation'],
});

export function structuredResult(raw, step, caseId, packageRoot, testFile) {
  const expected = BODY_NAMES[caseId]; require(expected, 'unknown ordinary body policy');
  const faults = [], failures = [], identities = [], names = new Set();
  const add = (ok, reason) => { if (!ok) faults.push(reason); };
  add(object(raw), 'structured report is not an object');
  add(step.executionStatus === 'completed' && step.exitCode === 0 && step.ownedGroupRetired === true,
    'provider nonzero exit, deadline, interruption, outside descendant or owned-group fault');
  add(raw?.success === true, 'provider success is not true');
  for (const field of ['errors', 'unhandledErrors', 'unhandledRejections']) add(empty(raw?.[field]), 'outside provider errors: ' + field);
  for (const field of ['numFailedTestSuites', 'numRuntimeErrorTestSuites', 'numFailedTests', 'numPendingTests', 'numTodoTests'])
    add(raw?.[field] === undefined || raw[field] === 0, 'nonzero provider fault/unfinished census: ' + field);
  const suites = Array.isArray(raw?.testResults) ? raw.testResults : [];
  add(suites.length > 0, 'no actual collected suite inventory');
  for (const suite of suites) {
    if (!object(suite)) { faults.push('non-object collected suite'); continue; }
    add(suite.status === 'passed', 'suite did not pass');
    for (const field of ['message', 'error', 'errors', 'failureMessage', 'failureMessages', 'testExecError'])
      add(empty(suite[field]), 'collection/setup/cleanup suite fault: ' + field);
    const file = typeof suite.name === 'string' ? resolve(suite.name) : '';
    add(file === resolve(packageRoot, testFile), 'unselected or unnamed collected suite');
    add(Array.isArray(suite.assertionResults), 'suite assertion census missing');
    for (const test of Array.isArray(suite.assertionResults) ? suite.assertionResults : []) {
      if (!object(test)) { faults.push('non-object test result'); continue; }
      const name = test.fullName;
      add(typeof name === 'string' && name.length > 0 && name === name.trim(), 'uncanonical full test name');
      const identity = file + '\0' + name;
      add(!names.has(identity), 'duplicate test identity'); names.add(identity);
      identities.push({ file, fullName: name, status: test.status });
      for (const field of ['failureMessages', 'errors', 'error', 'failureMessage', 'testExecError'])
        add(test.status === 'failed' || empty(test[field]), 'error attached to nominally passed/unfinished task: ' + field);
      if (test.status === 'failed') failures.push({ file, fullName: name, status: 'UnattributedTestFailure', errors: test.failureMessages ?? test.errors ?? [] });
      add(test.status === 'passed', 'body not completed/passed');
    }
  }
  const passed = identities.filter(row => row.status === 'passed').length;
  add(natural(raw?.numTotalTests) && raw.numTotalTests === identities.length, 'total test census mismatch');
  add(natural(raw?.numPassedTests) && raw.numPassedTests === passed, 'passed test census mismatch');
  add(identities.length === expected.length && expected.every(name => identities.some(row => row.fullName === name)), 'exact registered public/resource body census differs');
  return { passed: faults.length === 0, faults, failures, identities, expectedNames: expected,
    ordinaryTestEvidenceOnly: true, failurePhaseNotInferredFromSerializedMessage: true, verifiedRuntimeKillCredit: 0 };
}

function controlPair(resource, stages, kind) {
  const controls = resource.collectorControls;
  require(Array.isArray(controls) && controls.length === 2 && new Set(controls.map(c => c?.stage)).size === 2
    && stages.every(stage => controls.some(c => c?.stage === stage)), 'exact before/after collector controls absent');
  for (const c of controls) {
    require(object(c) && c.positiveRetained === true && c.negativeCollected === true && natural(c.attempts, 1) && c.attempts <= 24, 'collector capability control did not pass finitely');
    if (kind === 'private-key') require(c.algorithm === 'ECDH/P-256' && c.extractable === false, 'native nonextractable ECDH controls missing');
    if (kind === 'draft-tail') require(c.resource === 'fulfilled-native-Promise', 'native fulfilled Promise controls missing');
  }
}
const truths = (r, names, label) => require(object(r) && names.every(name => r[name] === true), label);

export function validateWitnesses(caseId, witnesses, nodeVersion) {
  const resource = witnesses.resource;
  require(object(resource) && /^v22\./.test(nodeVersion) && resource.nodeVersion === nodeVersion && resource.gcCapability === true,
    'actual exposed-GC Node22 resource capability absent');
  require(resource.stage === 'passed' && empty(resource.setupFailure), 'resource body did not complete a successful finite assertion');
  controlPair(resource, caseId === 'draft-tail' ? ['before-public-producers', 'after-public-producers'] : ['before-public-producer', 'after-public-producer'], caseId);
  if (caseId === 'private-key') {
    truths(resource.publicProducer, ['complete', 'password600kVerifierMatched', 'passwordOnlyProfileBlocked', 'acceptedPublicMfa', 'authenticatedIdentityEnvelopeOpened', 'actualCaseloadLoaded'], 'public authenticated key producer incomplete');
    truths(resource, ['observerRestoredBeforeUnmount', 'realUnmountCompleted'], 'native key observer/unmount retirement incomplete');
    require(natural(resource.observedNativePrivateKeys, 1) && resource.retainedPrivateKeyCount === 0
      && natural(resource.collectionAttempts, 1) && resource.collectionAttempts <= 21, 'native key collection observation incomplete');
  } else if (caseId === 'settled-slot') {
    const publicReceipt = witnesses.public;
    require(object(publicReceipt) && publicReceipt.result === 'PristinePublicWitnessPassed' && Array.isArray(publicReceipt.events)
      && publicReceipt.events.every((event, order) => object(event) && event.order === order && typeof event.name === 'string' && !event.name.startsWith('producer-barrier-')),
      'completed original public memo producer receipt absent');
    for (const name of ['A-shipped-entry-producer-bounds', 'A-actual-atomic-rotation-HTTP-committed', 'B-public-registration-HTTP-accepted', 'B-verified-unlock-public-completion', 'B-verified-unlock-restores-required-onboarding'])
      require(publicReceipt.events.some(event => event.name === name), 'mandatory public producer event absent: ' + name);
    truths(resource.publicProducer, ['complete', 'registeredReplacement', 'verifiedReplacementUnlock'], 'slot producer adoption incomplete');
    require(natural(resource.capturedPromiseAllocations, 100) && natural(resource.publicProducer.uniqueGeneratedChunkKeys, 29)
      && resource.publicProducer.boundedTypedEntries === 7 && resource.publicProducer.charactersPerTypedEntry === 99000 && resource.publicProducer.voiceEntries === 1
      && resource.retainedPromiseCount === 0 && Array.isArray(resource.retainedSlots) && resource.retainedSlots.length === 0, 'slot allocation/bounded producer/collection observation incomplete');
  } else if (caseId === 'local-rekey-tail') {
    truths(resource, ['observerRestoredBeforeCollection', 'actualRendererUnmountCompleted', 'originalFactoryPromisesForwardedUnchanged'], 'local rekey observer/renderer/original Promise retirement incomplete');
    require(natural(resource.originalFactoryPromisesForwarded, 16), 'four actual public factories not observed');
    truths(resource.publicProducer, ['complete', 'initialLoginCompleted'], 'original public Login incomplete');
    const rotations = resource.publicProducer.rotations, scopes = resource.allocationScopes, factories = ['markLocalRekeyPhase:credential', 'markLocalRekeyPhase:server', 'storeLocalRekeyRequest', 'storeLocalRekeyTokens'];
    require(resource.publicProducer.atomicCommits === 4 && Array.isArray(rotations) && rotations.length === 4
      && rotations.every((r,i) => object(r) && r.rotation === i+1), 'four ordered public atomic rotations absent');
    for (const [index,row] of rotations.entries()) {
      truths(row, ['committed', 'independentlyVerifiedServerProof', 'actualSuccessorUnlock', 'retainedLocalContent'], 'actual ciphertext/Unlock transition absent');
      require(['beforeEpoch','epoch','beforeGeneration','generation'].every(k => natural(row[k],1)) && row.epoch > row.beforeEpoch && row.generation > row.beforeGeneration, 'rotation scope did not advance');
      if (index) require(row.beforeEpoch === rotations[index-1].epoch && row.beforeGeneration === rotations[index-1].generation, 'disconnected public successor sequence');
    }
    require(Array.isArray(resource.observedFactoryTags) && resource.observedFactoryTags.length === 4
      && factories.every(name => resource.observedFactoryTags.includes(name)) && resource.distinctGenerationScopes === 4
      && natural(resource.capturedPromiseAllocations,48) && Array.isArray(scopes) && scopes.length === 4
      && new Set(scopes.map(s=>s.rotation)).size === 4 && new Set(scopes.map(s=>s.epoch+'\0'+s.generation)).size === 4, 'weak factory allocation census incomplete');
    for (const scope of scopes) {
      const row = rotations[scope.rotation-1];
      require(row && natural(scope.count,12) && object(scope.factoryCounts) && Object.keys(scope.factoryCounts).length === 4
        && factories.every(name => natural(scope.factoryCounts[name],1)) && Object.values(scope.factoryCounts).reduce((a,b)=>a+b,0) === scope.count
        && natural(scope.epoch,1) && natural(scope.generation,1) && row.beforeEpoch <= scope.epoch && scope.epoch <= row.epoch
        && row.beforeGeneration <= scope.generation && scope.generation <= row.generation, 'factory scope not bound to an actual public rotation');
    }
    require(scopes.reduce((sum,s)=>sum+s.count,0) === resource.capturedPromiseAllocations && resource.retainedPromiseCount === 0
      && Array.isArray(resource.retainedFactories) && resource.retainedFactories.length === 0, 'local rekey finite collection census differs');
  } else if (caseId === 'draft-tail') {
    truths(resource, ['originalProductionPromisesUnmodified', 'observerDisabledBeforeGc', 'actualAppUnmountCompleted', 'ownedRendererAndNativeMocksReleased'], 'draft original Promise/observer/renderer retirement incomplete');
    const stages = resource.publicProducerStages, retired = resource.completedPublicOwnerRetirements;
    require(resource.actualPublicOwnerCount === 2 && resource.actualPublicDraftScopeCount === 12 && Array.isArray(stages) && stages.length === 12
      && Array.isArray(retired) && retired.length === 2 && new Set(retired).size === 2 && retired.every(v=>typeof v==='string' && v), 'bounded public owner/chart census absent');
    const scopes = new Set(), counts = new Map();
    for (const stage of stages) {
      require(object(stage) && [stage.owner,stage.patient].every(v=>typeof v==='string' && v && !v.includes(':')) && natural(stage.commitCount,1), 'draft public owner/patient identity malformed');
      truths(stage, ['password600kAndMfa', 'actualChartWriting', 'actualBackNavigation', 'encryptedCommit', 'independentDraftAuthenticated'], 'authenticated completed public draft missing');
      const scope=stage.owner+':'+stage.patient; require(!scopes.has(scope), 'duplicate public draft scope'); scopes.add(scope); counts.set(stage.owner,(counts.get(stage.owner)??0)+1);
    }
    require(counts.size === 2 && retired.every(owner=>counts.get(owner)===6), 'owner retirement differs from completed chart census');
    const allocations = resource.allocations;
    require(natural(resource.observedNativePromiseCount,12) && Array.isArray(allocations) && allocations.length === resource.observedNativePromiseCount
      && new Set(allocations.map(a=>a.scope)).size === 12 && allocations.every(a=>object(a) && scopes.has(a.scope) && a.settled===true
        && typeof a.origin==='string' && a.origin.includes('savePortalDraft') && a.origin.includes('/src/noteDrafts.ts'))
      && resource.retainedNativePromiseCount === 0 && natural(resource.collectionAttempts,1) && resource.collectionAttempts <= 21, 'draft fulfilled native allocation/collection census incomplete');
  } else throw new Error('SetupError: unknown ordinary resource policy');
  return { caseId, passed: true, actualFinitePublicProducerAndResourceWitnessValidated: true, verifiedRuntimeKillCredit: 0 };
}

function filesUnder(directory) {
  const result=[]; const walk=(folder,ancestors=new Set())=>{ const real=realpathSync(folder);require(!ancestors.has(real),'cyclic runtime/input directory');const next=new Set(ancestors).add(real);for(const entry of readdirSync(folder,{withFileTypes:true})) {
    const path=join(folder,entry.name);
    const type=entry.isSymbolicLink()?statSync(path):entry;
    if(type.isDirectory()) walk(path,next);
    else if(type.isFile()) result.push(path);
  }}; walk(directory); return result.sort();
}
export function runtimeInventory(modules) {
  modules=realpathSync(modules);
  const version=JSON.parse(readFileSync(join(modules,'vitest/package.json'))).version;
  require(['4.1.10','4.1.11','5.0.1'].includes(version),'unsupported unqualified provider version: '+version);
  const splitRunner=version.startsWith('4.');
  for(const name of ['vitest','@vitest/spy','@vitest/mocker','vite','typescript','react','react-test-renderer','scheduler',...(splitRunner?['@vitest/runner','@vitest/expect','@vitest/utils','@vitest/snapshot']:[])])
    require(existsSync(join(modules,name,'package.json')), 'whole provider/compiler/consumer package absent: '+name);
  if(!splitRunner) require(existsSync(join(modules,'vitest/dist/task-utils.js')) && readdirSync(join(modules,'vitest/dist/chunks')).filter(name=>/^run\..*\.js$/.test(name)).length===1,'bundled provider runner/task-utils layout absent');
  const names=['vitest','@vitest','vite','@babel','@vitejs/plugin-react','@rolldown','rolldown','@oxc-project','@oxc-parser','@oxc-transform','@oxc-resolver','oxc-parser','oxc-transform','oxc-resolver','@esbuild','esbuild','typescript','react','react-dom','react-test-renderer','react-is','scheduler','fake-indexeddb','hermes-parser','hermes-estree','@react-native/babel-preset','@types/node','@types/react','@types/react-test-renderer','@types/chai','chai','expect-type','magic-string','es-module-lexer','obug','std-env','tinybench','tinyexec','tinyglobby','pathe','picomatch','why-is-node-running','tinyrainbow','csstype'];
  const hashes={}, queue=[], seen=new Set(), resolved=[];
  const add=folder=>{for(const file of filesUnder(folder))hashes[relative(modules,file)]=hashFile(file);};
  for(const name of names) if(existsSync(join(modules,name))) {
    const folder=join(modules,name);add(folder);
    if(existsSync(join(folder,'package.json')))queue.push(folder);
    else for(const entry of readdirSync(folder,{withFileTypes:true})) {
      const child=join(folder,entry.name);if(existsSync(join(child,'package.json')))queue.push(child);
    }
  }
  const findDependency=(folder,name)=>{
    for(let cursor=folder;;cursor=resolve(cursor,'..')) {
      const candidate=join(cursor,'node_modules',name);
      if(existsSync(join(candidate,'package.json')))return candidate;
      if(resolve(cursor,'..')===cursor)return null;
    }
  };
  while(queue.length) {
    const folder=queue.shift(), physical=realpathSync(folder);if(seen.has(physical))continue;seen.add(physical);
    add(folder);const manifest=JSON.parse(readFileSync(join(folder,'package.json')));
    resolved.push({path:physical,name:manifest.name,version:manifest.version,manifestSha256:hashFile(join(folder,'package.json'))});
    for(const name of new Set([...Object.keys(manifest.dependencies??{}),...Object.keys(manifest.optionalDependencies??{}),...Object.keys(manifest.peerDependencies??{})])) {
      const dependency=findDependency(folder,name);
      require(dependency || !Object.hasOwn(manifest.dependencies??{},name) || Object.hasOwn(manifest.optionalDependencies??{},name), 'declared provider runtime dependency absent: '+manifest.name+'/'+name);
      if(dependency)queue.push(dependency);
    }
  }
  return { modules, versions:Object.fromEntries(['vitest','vite','typescript','react','react-test-renderer','scheduler'].map(name=>[name,JSON.parse(readFileSync(join(modules,name,'package.json'))).version])),
    resolvedDependencyPackages:resolved, wholeProviderCompilerAndConsumerHashes:hashes, digest:hashObject(hashes) };
}
export function productInputs(packageRoot) {
  const files=[]; for(const name of ['src','tests']) files.push(...filesUnder(join(packageRoot,name)));
  for(const entry of readdirSync(packageRoot,{withFileTypes:true})) if(entry.isFile() && /\.(?:json|ts|tsx|js|mjs|cjs|html|css)$/.test(entry.name)) files.push(join(packageRoot,entry.name));
  const shared=resolve(packageRoot,'../shared'); if(existsSync(shared)) files.push(...filesUnder(shared));
  return Object.fromEntries(files.sort().map(path=>[path,hashFile(path)]));
}
export function recheckFiles(hashes) { for(const [path,sha] of Object.entries(hashes)) require(hashFile(path)===sha,'input/support bytes changed: '+path); }
