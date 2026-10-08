import {existsSync,mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {dirname,join} from 'node:path';
const contract=JSON.parse(readFileSync('shared/crisis_phrases.json','utf8'));
const discrepancies=[];const boundary0250=[];const stableLatinMarkedSuffix=[];let tested=0;
for(let cp=0;cp<=0x10ffff;cp++) {
 if(cp>=0xd800&&cp<=0xdfff) continue;
 tested++; const ch=String.fromCodePoint(cp);const d=ch.normalize('NFKD');const base=d[0];const tail=d.slice(1);
 if(base<'\u0250'&&/^[\u0300-\u036f]+/.test(tail)&&!/^[\u0300-\u036f]+$/.test(tail)) discrepancies.push({cp,decomposition:d});
 if(base==='\u0250'&&/^[\u0300-\u036f]+$/.test(tail)) boundary0250.push({cp,decomposition:d});
 if(ch.normalize('NFKC')===ch&&base<'\u0250'&&/[\u0300-\u036f]+$/.test(tail)&&!/^[\u0300-\u036f]+$/.test(tail)) stableLatinMarkedSuffix.push({cp,decomposition:d});
}
function literalCount(pattern,upper) {let depth=0,count=0,escaped=false;for(const ch of pattern){if(escaped){escaped=false;continue;}if(ch==='\\'){escaped=true;continue;}if(ch==='('||ch==='['){depth++;continue;}if(ch===')'||ch===']'){depth=Math.max(0,depth-1);continue;}if(depth===0&&ch>='a'&&upper(ch))count++;}return count;}
const patterns=[...contract.dialog,...contract.suppress_extra];
const classification=patterns.map(pattern=>({pattern,count:literalCount(pattern,ch=>ch<='z'),withoutUpper:literalCount(pattern,()=>true),exclusiveUpper:literalCount(pattern,ch=>ch<'z')}));
const changedClassifications=classification.filter(row=>(row.count>4)!==(row.withoutUpper>4)||(row.count>4)!==(row.exclusiveUpper>4));
const interleavedNonAscii=classification.filter(row=>row.count>4).flatMap(row=>{
 let depth=0;const characters=[];
 for(const ch of row.pattern){if(ch==='('||ch==='['){depth++;continue;}if(ch===')'||ch===']'){depth--;continue;}if(depth===0&&ch>'\u007f'&&/\p{L}/u.test(ch))characters.push(ch);}
 return characters.length?[{pattern:row.pattern,characters}]:[];
});
const overlaps=[];const compounds=contract.benign_compounds;const folded=compounds.map(x=>x.replace(/([a-z])\1+/g,'$1'));
const anchoredEndings=['die','dead','cutting','gone','on','up','out'];
const endingDecisions=patterns.flatMap(pattern=>[pattern,pattern.replace(/([a-z])\1+/g,'$1')]).map(pattern=>{
 const src=pattern.split('\\s+').join('\\|?').split('\\b').join('');const lastWord=src.match(/([a-z]+)\)?$/)?.[1];
 return {pattern,lastWord:lastWord??null,ends:lastWord!==undefined&&anchoredEndings.some(e=>lastWord.endsWith(e)),starts:lastWord!==undefined&&anchoredEndings.some(e=>lastWord.startsWith(e))};
});
const nonAsciiCasedPatternCharacters=[...new Set(patterns.join(''))].filter(ch=>ch>'\u007f'&&ch.toLowerCase()!==ch.toUpperCase());
const undefinedInputMatches=patterns.filter(pattern=>new RegExp(pattern,'i').test(undefined));
// Mask order matters only when one fixed compound contains another. Keep
// each actual engine's order, including the ill-formed arithmetic mutant.
function sortOrders(values) { return {original:values,correct:values.slice().sort((a,b)=>b.length-a.length),emptyComparator:values.slice().sort(()=>undefined),positiveComparator:values.slice().sort((a,b)=>b.length+a.length)}; }
const nodeMaskOrders={original:sortOrders(compounds),folded:sortOrders(folded)};
let javascriptCoreMaskOrders;
const jsc=process.env.JSC_BINARY??'/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc';
if(existsSync(jsc)) {
 const directory=mkdtempSync(join(tmpdir(),'crisis-sort-invariants-'));
 try {
  const path=join(directory,'sort.js');
  writeFileSync(path,`var compounds=${JSON.stringify(compounds)},folded=${JSON.stringify(folded)}; var orders=${sortOrders.toString()}; print(JSON.stringify({original:orders(compounds),folded:orders(folded)}));`);
  javascriptCoreMaskOrders={binary:jsc,binarySha256:createHash('sha256').update(readFileSync(jsc)).digest('hex'),orders:JSON.parse(execFileSync(jsc,[path],{encoding:'utf8'}))};
 } finally {rmSync(directory,{recursive:true,force:true});}
}
const maskGrowth={maskCount:compounds.filter(x=>/^[\x00-\x7f\s]*$/.test(x)).length,recurrence:'L(next)=2*L+1 for one empty global mask replaced with a space',emptyInputCharacters:2**27-1,sevenCharacterInputCharacters:8*2**27-1,finite:true};
for (const values of [compounds,folded])for(let i=0;i<values.length;i++)for(let j=i+1;j<values.length;j++)if(values[i].includes(values[j])||values[j].includes(values[i]))overlaps.push([values[i],values[j]]);
const result={node:process.version,v8:process.versions.v8,unicode:process.versions.unicode,sourceHashes:Object.fromEntries(['web/src/crisisDetect.ts','mobile/src/crisisDetect.ts','shared/crisis_phrases.json'].map(p=>[p,createHash('sha256').update(readFileSync(p)).digest('hex')])),unicodeScalarValuesTested:tested,latinNfkdPrefixWithoutFullMarkTail:discrepancies,latin0250WithCombiningTail:boundary0250,stableLatinMarkedSuffix,classification,changedClassifications,interleavedNonAscii,endingDecisions,changedEndingDecisions:endingDecisions.filter(row=>row.ends!==row.starts),compoundSubstringOverlaps:overlaps,regexSpecialCompounds:compounds.filter(x=>/[.*+?^${}()|[\]\\]/.test(x)),nonAsciiCompounds:compounds.filter(x=>!/^[\x00-\x7f\s]*$/.test(x)),multipleAdjacentWhitespaceCompounds:compounds.filter(x=>/\s\s/.test(x)),asciiMaskCount:compounds.filter(x=>/^[\x00-\x7f\s]*$/.test(x)).length,nonAsciiCasedPatternCharacters,undefinedInputMatches,nodeMaskOrders,javascriptCoreMaskOrders,maskGrowth};
const outputPath=process.argv[2]??'reports/frontend-mutation-2026-10-05/crisis-invariant-proof.json';
mkdirSync(dirname(outputPath),{recursive:true});
writeFileSync(outputPath,JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify({...result,classification:undefined,endingDecisions:undefined,sourceHashes:undefined,nodeMaskOrders:undefined,javascriptCoreMaskOrders:undefined}));
