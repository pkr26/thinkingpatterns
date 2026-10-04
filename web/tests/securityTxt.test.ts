/** RFC 9116 release-value validation and placeholder rejection. */
// @ts-nocheck

import { describe, expect, it } from "vitest";

import {
  SECURITY_TXT_PLACEHOLDERS,
  assertNoSecurityTxtPlaceholders,
  renderSecurityTxt,
  securityTxtPlaceholderFindings,
} from "../tools/securityTxt.mjs";

const TEMPLATE = `# RFC 9116 security contact for the Fathom patient web client.
Contact: mailto:security@example.com
Expires: 2027-09-26T00:00:00.000Z
Preferred-Languages: en, es
Canonical: https://app.example.com/.well-known/security.txt
`;

const FILLED = `Contact: mailto:security@mindpattern.health
Expires: 2027-09-26T00:00:00.000Z
Preferred-Languages: en, es
Canonical: https://app.mindpattern.health/.well-known/security.txt
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
    const halfFixed = TEMPLATE.replace("security@example.com", "security@mindpattern.health");
    expect(securityTxtPlaceholderFindings(halfFixed)).toEqual(["app.example.com"]);
  });

  it("renders a deployment-specific RFC 9116 file from validated release inputs", () => {
    const text = renderSecurityTxt(
      {
        contact: "mailto:security@mindpattern.health",
        canonical: "https://app.mindpattern.health/.well-known/security.txt",
        expires: "2027-03-01T00:00:00.000Z",
      },
      new Date("2026-10-04T00:00:00.000Z"),
    );
    expect(text).toContain("Contact: mailto:security@mindpattern.health");
    expect(text).toContain("Canonical: https://app.mindpattern.health/.well-known/security.txt");
    expect(securityTxtPlaceholderFindings(text)).toEqual([]);
  });

  it("rejects unsafe, stale, or placeholder release configuration", () => {
    const now = new Date("2026-10-04T00:00:00.000Z");
    expect(() => renderSecurityTxt({ contact: "security@example.org", canonical: "https://app.example.org/.well-known/security.txt", expires: "2027-03-01T00:00:00.000Z" }, now)).toThrow(/mailto: or https:/);
    expect(() => renderSecurityTxt({ contact: "mailto:security@example.com", canonical: "https://app.example.org/.well-known/security.txt", expires: "2027-03-01T00:00:00.000Z" }, now)).toThrow(/non-reserved deployment domain/);
    expect(() => renderSecurityTxt({ contact: "mailto:security@mindpattern.health", canonical: "http://app.mindpattern.health/.well-known/security.txt", expires: "2027-03-01T00:00:00.000Z" }, now)).toThrow(/HTTPS URL/);
    expect(() => renderSecurityTxt({ contact: "mailto:security@mindpattern.health", canonical: "https://app.mindpattern.health/.well-known/security.txt", expires: "2026-01-01T00:00:00.000Z" }, now)).toThrow(/future/);
  });

  it("rejects reserved documentation and local domains in both contact forms and canonical URLs", () => {
    const now = new Date("2026-10-04T00:00:00.000Z");
    const expires = "2027-03-01T00:00:00.000Z";
    const canonical = "https://app.mindpattern.health/.well-known/security.txt";
    for (const domain of [
      "example.com", "mail.example.net", "mindpattern.example.org",
      "example", "test", "invalid", "service.test", "service.invalid",
      "localhost", "api.localhost", "service.local", "internal",
      "127.0.0.1", "10.0.0.1", "[::1]",
    ]) {
      expect(() => renderSecurityTxt({ contact: `mailto:security@${domain}`, canonical, expires }, now)).toThrow(/non-reserved deployment domain/);
      expect(() => renderSecurityTxt({ contact: `https://${domain}/security`, canonical, expires }, now)).toThrow(/non-reserved deployment domain/);
      expect(() => renderSecurityTxt({ contact: "mailto:security@mindpattern.health", canonical: `https://${domain}/.well-known/security.txt`, expires }, now)).toThrow(/non-reserved deployment domain/);
    }
  });

  it("rejects URL userinfo and ambiguous mailto headers", () => {
    const now = new Date("2026-10-04T00:00:00.000Z");
    const expires = "2027-03-01T00:00:00.000Z";
    const canonical = "https://app.mindpattern.health/.well-known/security.txt";
    expect(() => renderSecurityTxt({ contact: "https://user:pass@app.mindpattern.health/security", canonical, expires }, now)).toThrow(/must not contain credentials/);
    expect(() => renderSecurityTxt({ contact: "mailto:security@mindpattern.health?subject=report", canonical, expires }, now)).toThrow(/one complete address/);
    expect(() => renderSecurityTxt({ contact: "mailto:first@mindpattern.health,second@mindpattern.health", canonical, expires }, now)).toThrow(/one complete address/);
    expect(() => renderSecurityTxt({ contact: "mailto:security@mindpattern.health", canonical: "https://user:pass@app.mindpattern.health/.well-known/security.txt", expires }, now)).toThrow(/must not contain credentials/);
  });
});
