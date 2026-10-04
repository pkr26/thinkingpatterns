/**
 * Fail closed on every npm advisory except the two exact advisory roots whose
 * installed source is repaired by the reviewed, hash-pinned backports.
 *
 * npm's v2 report represents propagated findings with string `via` edges
 * (package A -> package B -> advisory object). Every reported node is walked
 * to an advisory object below; missing references, cycles, empty paths, and
 * mixed allowed/unreviewed roots are errors. This prevents one allowed root
 * elsewhere in the report from masking a malformed or newly vulnerable node.
 */
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

export const ALLOWED_ADVISORIES = new Map([
  ["https://github.com/advisories/GHSA-vfj7-8cjw-p6xm", "braces"],
  ["https://github.com/advisories/GHSA-86w9-cpqp-85rv", "node-forge"],
]);

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Return the exact allowed advisory roots reached by every affected node. */
export function validateAuditGraph(report, allowed = ALLOWED_ADVISORIES) {
  if (report?.error || report?.auditReportVersion !== 2 || !isObject(report?.vulnerabilities)) {
    throw new Error(
      `npm audit failed before producing a supported report: ${JSON.stringify(report?.error ?? report)}`,
    );
  }

  const vulnerabilities = report.vulnerabilities;
  const graph = new Map();
  for (const [name, vulnerability] of Object.entries(vulnerabilities)) {
    if (!isObject(vulnerability)) {
      throw new Error(`npm audit vulnerability node ${JSON.stringify(name)} is not an object`);
    }
    if (vulnerability.name !== undefined && vulnerability.name !== name) {
      throw new Error(
        `npm audit vulnerability key/name mismatch: ${JSON.stringify(name)} != ${JSON.stringify(vulnerability.name)}`,
      );
    }
    if (!Array.isArray(vulnerability.via) || vulnerability.via.length === 0) {
      throw new Error(`npm audit vulnerability node ${JSON.stringify(name)} has no advisory path`);
    }

    const references = new Set();
    const roots = new Map();
    for (const via of vulnerability.via) {
      if (typeof via === "string") {
        if (!isObject(vulnerabilities[via])) {
          throw new Error(`npm audit vulnerability graph references missing node ${JSON.stringify(via)}`);
        }
        references.add(via);
        continue;
      }
      if (!isObject(via)) {
        throw new Error(`npm audit node ${JSON.stringify(name)} has an invalid via edge`);
      }
      const expectedPackage = allowed.get(via.url);
      if (!expectedPackage || via.name !== expectedPackage) {
        throw new Error(`Unreviewed npm advisory: ${via.name ?? "unknown"} ${via.url ?? "missing URL"}`);
      }
      roots.set(via.url, via.name);
    }
    graph.set(name, { references, roots });
  }

  // npm's report can contain legitimate dependency cycles (for example,
  // metro <-> metro-config) with an allowed advisory reachable through a
  // different edge. Resolve the complete graph to a fixed point instead of
  // treating that presentation detail as a waiver or an automatic failure.
  // A closed cycle with no reviewed advisory never gains a root and fails.
  let changed = true;
  while (changed) {
    changed = false;
    for (const { references, roots } of graph.values()) {
      for (const reference of references) {
        for (const [url, packageName] of graph.get(reference).roots) {
          if (!roots.has(url)) {
            roots.set(url, packageName);
            changed = true;
          }
        }
      }
    }
  }

  for (const [name, { roots }] of graph) {
    if (roots.size === 0) {
      throw new Error(
        `npm audit vulnerability node ${JSON.stringify(name)} resolves to no allowed advisory (unrooted cycle or empty path)`,
      );
    }
  }

  const advisories = new Map();
  for (const { roots } of graph.values()) {
    for (const [url, packageName] of roots) advisories.set(url, packageName);
  }
  return advisories;
}

export function validateAuditResult(report, status) {
  const advisories = validateAuditGraph(report);
  if (status === 0) {
    if (advisories.size !== 0 || Object.keys(report.vulnerabilities).length !== 0) {
      throw new Error("npm audit exited clean but still reported vulnerability nodes");
    }
    return advisories;
  }
  if (status !== 1) throw new Error(`npm audit failed operationally with exit status ${status}`);
  if (advisories.size === 0) throw new Error("npm audit failed but no reviewable advisory root was present");
  return advisories;
}

function main() {
  const audit = spawnSync("npm", ["audit", "--json", "--audit-level=moderate"], {
    cwd: new URL("../", import.meta.url),
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (audit.error) throw audit.error;

  let report;
  try {
    report = JSON.parse(audit.stdout);
  } catch (error) {
    process.stderr.write(audit.stderr || audit.stdout);
    throw new Error(`npm audit did not return JSON: ${error.message}`);
  }

  let advisories;
  try {
    advisories = validateAuditResult(report, audit.status);
  } catch (error) {
    process.stderr.write(audit.stderr || "");
    throw error;
  }

  if (audit.status === 0) {
    console.log("npm dependency audit clean: no moderate-or-higher advisories.");
    return;
  }
  const totals = report.metadata?.vulnerabilities ?? {};
  console.log(
    `npm registry reports ${Object.keys(report.vulnerabilities).length} affected dependency nodes ` +
      `(${totals.moderate ?? 0} moderate, ${totals.high ?? 0} high, ${totals.critical ?? 0} critical), ` +
      `all resolving exclusively to the ${advisories.size} exact advisories covered by verified backports:`,
  );
  for (const [url, name] of [...advisories].sort()) console.log(`- ${name}: ${url}`);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main();
