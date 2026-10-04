import assert from "node:assert/strict";
import test from "node:test";

import { validateAuditResult } from "./audit_dependencies.mjs";

const braces = {
  name: "braces",
  url: "https://github.com/advisories/GHSA-vfj7-8cjw-p6xm",
};

function report(vulnerabilities) {
  return { auditReportVersion: 2, vulnerabilities, metadata: { vulnerabilities: {} } };
}

test("accepts a fully resolved propagated chain to an exact reviewed advisory", () => {
  const roots = validateAuditResult(
    report({
      braces: { name: "braces", via: [braces] },
      micromatch: { name: "micromatch", via: ["braces"] },
      parent: { name: "parent", via: ["micromatch"] },
    }),
    1,
  );
  assert.deepEqual([...roots], [[braces.url, "braces"]]);
});

test("rejects a string-only node that references no reported vulnerability", () => {
  assert.throws(
    () => validateAuditResult(report({ parent: { name: "parent", via: ["missing"] } }), 1),
    /references missing node/,
  );
});

test("rejects an unrooted cycle", () => {
  assert.throws(
    () =>
      validateAuditResult(
        report({ a: { name: "a", via: ["b"] }, b: { name: "b", via: ["a"] } }),
        1,
      ),
    /unrooted cycle/,
  );
});

test("accepts a dependency cycle only when the component reaches an exact reviewed root", () => {
  const roots = validateAuditResult(
    report({
      braces: { name: "braces", via: [braces] },
      a: { name: "a", via: ["b"] },
      b: { name: "b", via: ["a", "braces"] },
    }),
    1,
  );
  assert.deepEqual([...roots], [[braces.url, "braces"]]);
});

test("rejects a mixed path containing any unreviewed advisory", () => {
  assert.throws(
    () =>
      validateAuditResult(
        report({
          braces: { name: "braces", via: [braces] },
          mixed: {
            name: "mixed",
            via: ["braces", { name: "new-package", url: "https://example.invalid/new" }],
          },
        }),
        1,
      ),
    /Unreviewed npm advisory/,
  );
});

test("rejects key/name mismatches, empty paths, and operational failures", () => {
  assert.throws(
    () => validateAuditResult(report({ key: { name: "other", via: [braces] } }), 1),
    /key\/name mismatch/,
  );
  assert.throws(
    () => validateAuditResult(report({ empty: { name: "empty", via: [] } }), 1),
    /has no advisory path/,
  );
  assert.throws(() => validateAuditResult(report({}), 2), /operationally/);
});

test("accepts a genuinely empty successful report and rejects contradictory status", () => {
  assert.equal(validateAuditResult(report({}), 0).size, 0);
  assert.throws(
    () => validateAuditResult(report({ braces: { name: "braces", via: [braces] } }), 0),
    /exited clean/,
  );
});
