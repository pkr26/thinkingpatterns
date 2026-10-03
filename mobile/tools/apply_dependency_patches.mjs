/** Fail-closed exact-source backports. Never changes package versions,
 * never downloads code, and rejects upstream drift until it is reviewed. */
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const root = fileURLToPath(new URL('../', import.meta.url));
const patchRoot = path.join(root, 'tools/dependency-patches');
const manifest = JSON.parse(await readFile(path.join(patchRoot, 'manifest.json'), 'utf8'));
const lock = JSON.parse(await readFile(path.join(root, 'package-lock.json'), 'utf8'));
const sha = data => createHash('sha256').update(data).digest('hex');
const writes = [];
// Verify every input first; reject a partial or unfamiliar installation.
for (const pkg of manifest.packages) {
  const locations = Object.keys(lock.packages).filter(location => location === `node_modules/${pkg.name}` || location.endsWith(`/node_modules/${pkg.name}`));
  if (!locations.length) throw new Error(`Missing locked backport dependency: ${pkg.name}`);
  for (const location of locations) {
  const installed = path.join(root, location);
  const metadata = JSON.parse(await readFile(path.join(installed, 'package.json'), 'utf8'));
  if (metadata.version !== pkg.version) throw new Error(`Review security backport for ${pkg.name}@${metadata.version}`);
  for (const file of pkg.files) {
    const target = path.join(installed, file.path);
    const replacement = await readFile(path.join(patchRoot, pkg.name, file.path));
    if (sha(replacement) !== file.after) throw new Error(`Damaged patch artifact: ${pkg.name}/${file.path}`);
    const current = sha(await readFile(target));
    if (current === file.after) continue;
    if (current !== file.before) throw new Error(`Unexpected upstream source: ${pkg.name}/${file.path}`);
    writes.push([target, replacement]);
  }
  }
}
for (const [target, replacement] of writes) await writeFile(target, replacement);
console.log(`Verified dependency backports (${writes.length} source files applied).`);
