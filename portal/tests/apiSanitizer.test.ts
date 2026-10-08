import { afterEach, expect, it, vi } from "vitest";
import { detailToMessage, normalizeApiBaseUrl, sanitizeDetail, setSession, clearSession } from "../src/api";

afterEach(() => { clearSession(); vi.unstubAllEnvs(); });

it("keeps the exact error-copy length boundary and truncates only longer text", () => {
  expect(sanitizeDetail("x".repeat(199))).toBe("x".repeat(199));
  expect(sanitizeDetail("x".repeat(200))).toBe("x".repeat(200));
  expect(sanitizeDetail("x".repeat(201))).toBe(`${"x".repeat(200)}…`);
  expect(sanitizeDetail("  stable\tclient\ncopy  ")).toBe("stable client copy");
});

it.each([
  ...Array.from({ length: 32 }, (_, point) => point), 127,
])("separates control character U+%s without joining visible words", point => {
  expect(sanitizeDetail(`before${String.fromCharCode(point)}after`)).toBe("before after");
});

it.each([
  ...Array.from({ length: 5 }, (_, index) => 0x200b + index),
  ...Array.from({ length: 5 }, (_, index) => 0x202a + index),
  ...Array.from({ length: 16 }, (_, index) => 0x2060 + index), 0xfeff,
])("removes invisible U+%s before recognizing a split phishing domain", point => {
  expect(sanitizeDetail(`See evil${String.fromCharCode(point)}.example/help now`)).toBe("See now");
  expect(sanitizeDetail(`before${String.fromCharCode(point)}after`)).toBe("beforeafter");
});

it.each([
  "HTTP://evil.example/help", "https://evil.example/help", "ftp://evil.example/help",
  "x2+custom.scheme-name://payload", "EVIL-APP://payload", "a://payload",
  "evil.example", "a-b.example", "sub.evil.example:8443/help", "EVIL.EXAMPLE/help",
  "1evil.example/help", "evil.aa/help", `evil.${"a".repeat(24)}/help`,
  "555-0134", "5 (550) 134", "5.550.134", "555 0134", "1234",
])("removes a full URL/domain/phone token from surrounding actionable copy: %s", token => {
  expect(sanitizeDetail(`Try ${token} again`)).toBe("Try again");
});

it("maps untrusted validation details to safe ordered client copy", () => {
  expect(detailToMessage([{ msg: "first issue" }, { msg: "second issue" }], 422)).toBe("first issue; second issue");
  expect(detailToMessage([null, {}, { msg: 42 }, "detail"], 422)).toBe("invalid field; invalid field; invalid field; invalid field");
  for (const detail of [[], null, undefined, 42, {}, ""]) {
    expect(detailToMessage(detail, 422)).toBe("request failed (422)");
  }
  expect(detailToMessage([{ msg: "http://payload" }], 422)).toBe("request failed (422)");
});

it("discards standalone schemes and retains boundaries around removed phone text", () => {
  for (const token of ["http://payload", "https://payload", "ftp://payload", "custom://payload", "a://payload"]) expect(sanitizeDetail(token)).toBe("");
  expect(sanitizeDetail("before1234after")).toBe("before after");
  expect(sanitizeDetail("Try ahttp://payload again")).toBe("Try a again");
  expect(sanitizeDetail("Try http:// payload again")).toBe("Try http:// payload again");
});

it("normalizes Unicode edge whitespace and slashes created by URL parsing", () => {
  expect(normalizeApiBaseUrl("\u00a0https://clinic.example/path///\u00a0")).toBe("https://clinic.example/path");
  expect(normalizeApiBaseUrl("https://clinic.example/path\\\\")).toBe("https://clinic.example/path");
});

it("allows HTTP loopback only in development or test builds", () => {
  vi.stubEnv("DEV", false);
  vi.stubEnv("MODE", "production");
  expect(normalizeApiBaseUrl("http://localhost:8000")).toBe("");
  expect(() => setSession("bearer", "http://localhost:8000")).toThrow("use an HTTPS server URL");
  expect(normalizeApiBaseUrl("https://clinic.example/")).toBe("https://clinic.example");
  vi.stubEnv("DEV", true);
  expect(normalizeApiBaseUrl("http://localhost:8000")).toBe("http://localhost:8000");
  vi.stubEnv("DEV", false);
  vi.stubEnv("MODE", "test");
  expect(normalizeApiBaseUrl("http://localhost:8000")).toBe("http://localhost:8000");
  expect(normalizeApiBaseUrl("http://127.0.0.1:8000")).toBe("http://127.0.0.1:8000");
  expect(normalizeApiBaseUrl("http://[::1]:8000")).toBe("http://[::1]:8000");
  expect(normalizeApiBaseUrl("http://localhost.evil.example:8000")).toBe("");
});
