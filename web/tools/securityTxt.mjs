/**
 * RFC 9116 release generator and validation. The generic public/ tree has no
 * security.txt: tagged builds create it from required deployment values so a
 * plausible-looking example contact can never ship by accident.
 */
import { isIP } from "node:net";

/** The example markers the template ships with — a finding for each one
 *  still present verbatim in the file. */
export const SECURITY_TXT_PLACEHOLDERS = ["security@example.com", "app.example.com"];

/** Which placeholder markers `text` still carries (empty = clean). */
export function securityTxtPlaceholderFindings(text) {
  return SECURITY_TXT_PLACEHOLDERS.filter((marker) => text.includes(marker));
}

/** Throw with the honest operator-facing message when any placeholder
 *  survives; return silently when the file is deployment-ready. */
export function assertNoSecurityTxtPlaceholders(text) {
  const findings = securityTxtPlaceholderFindings(text);
  if (findings.length > 0) {
    throw new Error(
      `security.txt input still contains placeholder marker(s): ${findings.join(", ")} — ` +
        "replace the example contact and canonical URL with the real operator values before shipping.",
    );
  }
}

function isReservedDeploymentHostname(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "example" ||
    host === "test" ||
    host === "invalid" ||
    host === "example.com" ||
    host.endsWith(".example.com") ||
    host === "example.net" ||
    host.endsWith(".example.net") ||
    host === "example.org" ||
    host.endsWith(".example.org") ||
    host.endsWith(".example") ||
    host.endsWith(".test") ||
    host.endsWith(".invalid") ||
    host.endsWith(".local")
  );
}

function assertDeploymentHostname(hostname, field) {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  const ipCandidate = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  const labels = host.split(".");
  const syntacticallyPublic =
    labels.length >= 2 &&
    labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)) &&
    /^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/i.test(labels.at(-1));
  if (!host || isIP(ipCandidate) !== 0 || !syntacticallyPublic || isReservedDeploymentHostname(host)) {
    throw new Error(`${field} must use the operator's real, non-reserved deployment domain`);
  }
}

/** Render a deployment-specific RFC 9116 file from release configuration. */
export function renderSecurityTxt({ contact, canonical, expires }, now = new Date()) {
  for (const [name, value] of Object.entries({ contact, canonical, expires })) {
    if (typeof value !== "string" || value.trim() !== value || value.length === 0 || /[\r\n]/.test(value)) {
      throw new Error(`SECURITY_TXT_${name.toUpperCase()} must be a non-empty single-line value with no surrounding whitespace`);
    }
  }
  let contactUrl;
  try { contactUrl = new URL(contact); } catch { throw new Error("SECURITY_TXT_CONTACT must be a mailto: or https: URL"); }
  if (!["mailto:", "https:"].includes(contactUrl.protocol)) {
    throw new Error("SECURITY_TXT_CONTACT must be a mailto: or https: URL");
  }
  if (contactUrl.protocol === "https:") {
    if (contactUrl.username || contactUrl.password) {
      throw new Error("SECURITY_TXT_CONTACT HTTPS URL must not contain credentials");
    }
    assertDeploymentHostname(contactUrl.hostname, "SECURITY_TXT_CONTACT");
  } else {
    let address;
    try { address = decodeURIComponent(contactUrl.pathname); } catch { address = ""; }
    const at = address.lastIndexOf("@");
    if (
      at <= 0 ||
      at !== address.indexOf("@") ||
      at === address.length - 1 ||
      address.includes(",") ||
      /\s|[\x00-\x1f\x7f]/.test(address) ||
      contactUrl.search ||
      contactUrl.hash
    ) {
      throw new Error("SECURITY_TXT_CONTACT mailto: URL must contain one complete address");
    }
    assertDeploymentHostname(address.slice(at + 1), "SECURITY_TXT_CONTACT");
  }
  let canonicalUrl;
  try { canonicalUrl = new URL(canonical); } catch { throw new Error("SECURITY_TXT_CANONICAL must be an HTTPS URL ending in /.well-known/security.txt"); }
  if (canonicalUrl.protocol !== "https:" || !canonicalUrl.pathname.endsWith("/.well-known/security.txt")) {
    throw new Error("SECURITY_TXT_CANONICAL must be an HTTPS URL ending in /.well-known/security.txt");
  }
  if (canonicalUrl.username || canonicalUrl.password || canonicalUrl.search || canonicalUrl.hash) {
    throw new Error("SECURITY_TXT_CANONICAL must not contain credentials, query parameters, or fragments");
  }
  assertDeploymentHostname(canonicalUrl.hostname, "SECURITY_TXT_CANONICAL");
  const expiry = new Date(expires);
  if (Number.isNaN(expiry.valueOf()) || expiry.toISOString() !== expires) {
    throw new Error("SECURITY_TXT_EXPIRES must be an ISO-8601 UTC timestamp such as 2027-04-01T00:00:00.000Z");
  }
  const remaining = expiry.valueOf() - now.valueOf();
  if (remaining <= 0 || remaining > 366 * 24 * 60 * 60 * 1000) {
    throw new Error("SECURITY_TXT_EXPIRES must be in the future and no more than 366 days away");
  }
  const rendered = [
    "# Generated for this release; source configuration is held by the deployer.",
    `Contact: ${contact}`,
    `Expires: ${expires}`,
    "Preferred-Languages: en, es",
    `Canonical: ${canonical}`,
    "",
  ].join("\n");
  assertNoSecurityTxtPlaceholders(rendered);
  return rendered;
}
