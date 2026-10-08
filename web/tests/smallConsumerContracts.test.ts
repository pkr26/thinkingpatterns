import { afterEach, describe, expect, it } from "vitest";
import { ApiError } from "../src/api/client";
import { localDateISO } from "../src/dates";
import { displayError } from "../src/errors";
import { accountKeyPolicy, keyBelongsToOwner } from "../src/ownerStorage";
import { __setLocaleForTests, t } from "../src/strings";

afterEach(() => __setLocaleForTests("en"));

describe("local calendar and safe visible errors", () => {
  it.each([[9, 0, 1, "0009-01-01"], [99, 1, 9, "0099-02-09"], [2026, 9, 5, "2026-10-05"], [2024, 1, 29, "2024-02-29"], [2026, 11, 31, "2026-12-31"]] as const)
    ("formats local calendar fields including padded years, months and days", (year, month, day, expected) => {
      const morning = new Date(2000, month, day, 0, 1); morning.setFullYear(year);
      const evening = new Date(2000, month, day, 23, 59); evening.setFullYear(year);
      expect(localDateISO(morning)).toBe(expected); expect(localDateISO(evening)).toBe(expected);
    });

  it.each([[0, "errors.offline"], [401, "errors.sessionExpired"], [403, "errors.forbidden"], [404, "errors.notFound"], [409, "errors.conflict"], [413, "errors.tooLarge"], [429, "errors.rateLimited"], [500, "errors.serverError"], [599, "errors.serverError"]] as const)
    ("localizes the visible explanation for HTTP status %i without rendering server detail", (status, key) => {
      for (const locale of ["en", "es"] as const) {
        __setLocaleForTests(locale);
        expect(displayError(new ApiError(status, "untrusted server-controlled detail"), "safe fallback")).toBe(t(key));
      }
    });

  it("uses safe fallback for other server errors and preserves locally-authored client errors", () => {
    for (const status of [200, 400, 402, 405, 410, 414, 428, 430, 499]) expect(displayError(new ApiError(status, "hostile detail"), "safe fallback")).toBe("safe fallback");
    expect(displayError(new Error("Keep local writing for recovery"), "fallback")).toBe("Keep local writing for recovery");
    for (const message of ["", " ", "\n\t"]) expect(displayError(new Error(message), "visible fallback")).toBe("visible fallback");
    for (const value of [null, undefined, false, "untyped failure", { message: "untrusted object" }]) expect(displayError(value, "fallback")).toBe("fallback");
  });
});

describe("account storage policy consumed by erasure and commit fencing", () => {
  it.each([
    ["mindpattern.draft.active.", true], ["mindpattern.safetyPlan.", true], ["mindpattern.moodlog.", true],
    ["mindpattern.feedback.", true], ["mindpattern.pendingMeasure.", true], ["mindpattern.patternMutes.v1.", true],
    ["mindpattern.entryVersions.", true], ["mindpattern.entryV2Bound.", true],
    ["mindpattern.measureCadence.", false], ["mindpattern.thresholdNotice.v1.", false], ["mindpattern.stateSeq.", false],
    ["mindpattern.localRotation.", false], ["mindpattern.rotationSalt.", false], ["mindpattern.rotationSeed.", false],
    ["mindpattern.rotatePendingSalt.", false], ["mindpattern.rekeyHint.", false], ["mindpattern.onboarding.v1.", false], ["mindpattern.mutedPids.v1.", false],
  ] as const)("binds %s to exactly its owner and required content-key policy", (prefix, keyBound) => {
    expect(accountKeyPolicy(`${prefix}owner-A`)).toEqual({ owner: "owner-A", keyBound });
    expect(keyBelongsToOwner(`${prefix}owner-A`, "owner-A")).toBe(true);
    expect(keyBelongsToOwner(`${prefix}owner-A`, "owner-B")).toBe(false);
    expect(accountKeyPolicy(prefix)).toBeNull();
    expect(accountKeyPolicy(`unrelated.${prefix}owner-A`)).toBeNull();
  });

  it.each(["items", "rejected", "quarantine", "evictions"])("decodes the %s queue owner from its actual origin/account scope", (kind) => {
    const scope = Buffer.from("https://fathom.test\0owner-A", "utf8").toString("base64url");
    const slot = `mindpattern/queue.v1.${kind}.${scope}`;
    expect(accountKeyPolicy(slot)).toEqual({ owner: "owner-A", keyBound: kind !== "evictions" });
    expect(keyBelongsToOwner(slot, "owner-A")).toBe(true);
    expect(keyBelongsToOwner(slot, "owner-B")).toBe(false);
    expect(accountKeyPolicy(`prefix.${slot}`)).toBeNull();
    expect(accountKeyPolicy(`${slot}.suffix`)).toBeNull();
  });

  it("rejects queue scopes with missing account separators, empty owners, invalid base64 or invalid namespaces", () => {
    for (const raw of ["https://fathom.test", "https://fathom.test\0", ""]) {
      expect(accountKeyPolicy(`mindpattern/queue.v1.items.${Buffer.from(raw).toString("base64url")}`)).toBeNull();
    }
    for (const slot of ["mindpattern/queue.v1.items.a", "mindpattern/queue.v1.items.@@@", "mindpattern/queue.v2.items.aA", "mindpattern/queue.v1.other.aA", "other.storage.owner-A"]) {
      expect(accountKeyPolicy(slot)).toBeNull(); expect(keyBelongsToOwner(slot, "owner-A")).toBe(false);
    }
  });

  it.each(["abþ", "abÿ", "ab߿"])("preserves UTF-8 owners across URL-safe queue scope decoding: %s", (owner) => {
    const scope = Buffer.from(`https://fathom.test\0${owner}`, "utf8").toString("base64url");
    expect(accountKeyPolicy(`mindpattern/queue.v1.items.${scope}`)).toEqual({ owner, keyBound: true });
    expect(keyBelongsToOwner(`mindpattern/queue.v1.items.${scope}`, owner)).toBe(true);
  });
});
