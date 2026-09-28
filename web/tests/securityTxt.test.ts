/** The security.txt placeholder gate's check function (audit 2026-09-28,
 *  INFO): `npm run build` fails while public/.well-known/security.txt
 *  still carries the template's example contact/URL. These pins hold the
 *  CHECK itself — the repo legitimately ships the template until an
 *  operator fills it in, at which point the build gate goes green. */
import { describe, expect, it } from "vitest";

import {
  SECURITY_TXT_PLACEHOLDERS,
  assertNoSecurityTxtPlaceholders,
  securityTxtPlaceholderFindings,
} from "../tools/securityTxt.mjs";

const TEMPLATE = `# RFC 9116 security contact for the MindPattern patient web client.
Contact: mailto:security@example.com
Expires: 2027-09-26T00:00:00.000Z
Preferred-Languages: en, es
Canonical: https://app.example.com/.well-known/security.txt
`;

const FILLED = `Contact: mailto:security@mindpattern.example.org
Expires: 2027-09-26T00:00:00.000Z
Preferred-Languages: en, es
Canonical: https://app.mindpattern.example.org/.well-known/security.txt
`;

describe("security.txt placeholder gate (audit 2026-09-28 INFO)", () => {
  it("flags every example marker the template ships with", () => {
    expect(securityTxtPlaceholderFindings(TEMPLATE)).toEqual([...SECURITY_TXT_PLACEHOLDERS]);
  });

  it("a deployment-ready file carries no findings", () => {
    expect(securityTxtPlaceholderFindings(FILLED)).toEqual([]);
  });

  it("the assert form throws with the operator-facing message on placeholders", () => {
    expect(() => assertNoSecurityTxtPlaceholders(TEMPLATE)).toThrow(/placeholder marker\(s\): security@example\.com, app\.example\.com/);
    expect(() => assertNoSecurityTxtPlaceholders(FILLED)).not.toThrow();
  });

  it("one marker removed still fails the gate on the survivor", () => {
    const halfFixed = TEMPLATE.replace("security@example.com", "security@mindpattern.example.org");
    expect(securityTxtPlaceholderFindings(halfFixed)).toEqual(["app.example.com"]);
  });
});
