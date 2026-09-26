/** XSS floor (WEB_PLAN P1.7): the app renders decrypted journal text, so
 *  raw-HTML sinks are forbidden outright in src/. React's escaping is the
 *  only path from data to markup; this scan keeps it that way and the P9
 *  red-team corpus builds on it. */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const FORBIDDEN = [
  "dangerouslySetInnerHTML",
  ".innerHTML",
  ".outerHTML",
  "insertAdjacentHTML",
  "document.write",
];

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...sourceFiles(full));
    else if (/\.(ts|tsx)$/.test(entry)) out.push(full);
  }
  return out;
}

describe("no raw-HTML sinks in src/", () => {
  it("never assigns innerHTML/outerHTML or uses dangerouslySetInnerHTML", () => {
    const offenders: string[] = [];
    for (const file of sourceFiles(join(import.meta.dirname, "..", "src"))) {
      const contents = readFileSync(file, "utf8");
      for (const token of FORBIDDEN) {
        if (contents.includes(token)) offenders.push(`${file}: ${token}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});
