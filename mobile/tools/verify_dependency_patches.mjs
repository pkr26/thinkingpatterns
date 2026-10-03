import './apply_dependency_patches.mjs';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
const require = createRequire(import.meta.url);
const braces = require('braces');
const forge = require('node-forge');
for (const relative of ['../node_modules/expo-modules-autolinking/android/expo-gradle-plugin/build.gradle.kts', '../node_modules/expo-modules-core/expo-module-gradle-plugin/build.gradle.kts']) {
  assert.match(readFileSync(new URL(relative, import.meta.url), 'utf8'), /kotlin\("jvm"\) version "2\.2\.21"/);
}
assert.match(readFileSync(new URL('../android/build.gradle', import.meta.url), 'utf8'), /kotlinVersion\s*=\s*"2\.2\.21"/);
assert.match(readFileSync(new URL('../android/gradle/wrapper/gradle-wrapper.properties', import.meta.url), 'utf8'), /gradle-9\.4\.1-bin\.zip/);
const libraryExtension = readFileSync(new URL('../node_modules/expo-modules-core/expo-module-gradle-plugin/src/main/kotlin/expo/modules/plugin/android/AndroidLibraryExtension.kt', import.meta.url), 'utf8');
assert.match(libraryExtension, /this@defaultConfig\.minSdk = minSdk/);
assert.doesNotMatch(libraryExtension, /this@defaultConfig\.targetSdk\s*=/);
assert.match(readFileSync(new URL('../node_modules/expo-modules-core/android/cmake/main.cmake', import.meta.url), 'utf8'), /"\$\{REACT_NATIVE_DIR\}\/ReactCommon"/);
assert.deepEqual(braces.expand('src/{a,b}/**/*.{ts,tsx}'), ['src/a/**/*.ts', 'src/a/**/*.tsx', 'src/b/**/*.ts', 'src/b/**/*.tsx']);
assert.equal(braces.compile('a/{b,c}/d'), 'a/(b|c)/d');
for (const method of ['compile', 'expand', 'stringify', 'parse']) {
  assert.throws(() => braces[method]('{'.repeat(4000) + 'x' + '}'.repeat(4000)), /exceeds max depth/);
  assert.throws(() => braces[method]('('.repeat(4000) + 'x' + ')'.repeat(4000), { maxDepth: Infinity }), /exceeds max depth/);
}
// Direct AST callers must receive the same bound as string callers.
let ast = { type: 'text', value: 'x' };
for (let i = 0; i < 1000; i++) ast = { type: 'root', nodes: [ast] };
for (const method of ['compile', 'expand', 'stringify']) assert.throws(() => braces[method](ast), /exceeds max depth/);

const pair = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 3 });
const privateKey = forge.pki.privateKeyFromPem(pair.privateKey.export({ type: 'pkcs1', format: 'pem' }).toString());
const publicKey = forge.pki.publicKeyFromPem(pair.publicKey.export({ type: 'pkcs1', format: 'pem' }).toString());
const digest = forge.md.sha256.create().update('verification regression');
assert.equal(publicKey.verify(digest.digest().getBytes(), privateKey.sign(digest)), true);
const A = forge.asn1;
const node = (type, constructed, value) => A.create(A.Class.UNIVERSAL, type, constructed, value);
for (const withNull of [false, true]) {
  const algorithm = [node(A.Type.OID, false, A.oidToDer(forge.oids.sha256).getBytes())];
  if (withNull) algorithm.push(node(A.Type.NULL, false, ''));
  const payload = () => A.toDer(node(A.Type.SEQUENCE, true, [node(A.Type.SEQUENCE, true, algorithm), node(A.Type.OCTETSTRING, false, digest.digest().getBytes())])).getBytes();
  assert.equal(publicKey.verify(digest.digest().getBytes(), privateKey.sign(payload(), 'NONE')), true);
  algorithm.push(node(A.Type.OCTETSTRING, false, 'attacker-controlled interior bytes'));
  const malformed = privateKey.sign(payload(), 'NONE');
  assert.throws(() => publicKey.verify(digest.digest().getBytes(), malformed), /valid RSASSA-PKCS1-v1_5 DigestInfo/);
}
console.log('Dependency regressions passed: bounded nested patterns and strict nested DigestAlgorithm, including valid inputs.');
