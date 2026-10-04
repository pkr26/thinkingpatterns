import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import { renderSecurityTxt } from "./securityTxt.mjs";

const output = resolve(import.meta.dirname, "../dist/.well-known/security.txt");
const text = renderSecurityTxt({
  contact: process.env.SECURITY_TXT_CONTACT,
  canonical: process.env.SECURITY_TXT_CANONICAL,
  expires: process.env.SECURITY_TXT_EXPIRES,
});
await mkdir(dirname(output), { recursive: true });
await writeFile(output, text, { encoding: "utf8", mode: 0o644 });
console.log(`Generated deployment security.txt at ${output}`);
