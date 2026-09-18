/**
 * API client hardening regressions: server-URL policy (the remote enabler
 * of credential interception) and error-detail sanitization (a hostile
 * server must not phish through our own dialogs).
 */
import { describe, expect, it } from "vitest";

import { parseServerUrl, detailToMessage } from "../src/api/client";

describe("parseServerUrl", () => {
  it("accepts https servers and normalizes trailing slashes", () => {
    expect(parseServerUrl("https://api.example.com/")).toEqual({
      url: "https://api.example.com",
      insecure: false,
    });
    expect(parseServerUrl("https://api.example.com:8443/v1/")).toEqual({
      url: "https://api.example.com:8443/v1",
      insecure: false,
    });
    // Multiple trailing slashes collapse; inner path segments are kept.
    expect(parseServerUrl("https://api.example.com/v1///")).toEqual({
      url: "https://api.example.com/v1",
      insecure: false,
    });
    // Whitespace around the input is trimmed.
    expect(parseServerUrl("  https://api.example.com  ")).toEqual({
      url: "https://api.example.com",
      insecure: false,
    });
  });

  it("allows plain http only for loopback development servers", () => {
    expect(parseServerUrl("http://localhost:8000")!.insecure).toBe(false);
    expect(parseServerUrl("http://127.0.0.1:8000")!.insecure).toBe(false);
    expect(parseServerUrl("http://[::1]:8000")!.insecure).toBe(false);
  });

  it("requires the scheme at the very start (anchored match)", () => {
    expect(parseServerUrl("xxhttps://api.example.com")).toBeNull();
    expect(parseServerUrl("https://api.example.com junk")).toBeNull();
  });

  it("rejects any unbracketed host with multiple colons, however spaced", () => {
    // The two-colon detector must catch wide gaps too, not just :x:.
    expect(parseServerUrl("http://ab:cd:ef:8000")).toBeNull();
    expect(parseServerUrl("http://1:2::3:8000")).toBeNull();
  });

  it("flags non-loopback http as insecure", () => {
    const parsed = parseServerUrl("http://nas.lan:8000");
    expect(parsed?.insecure).toBe(true);
    expect(parsed?.url).toBe("http://nas.lan:8000");
  });

  it("rejects credential-stuffed, malformed and non-HTTP URLs", () => {
    expect(parseServerUrl("https://user:pass@evil.example")).toBeNull();
    expect(parseServerUrl("ftp://example.com")).toBeNull();
    expect(parseServerUrl("not a url")).toBeNull();
    expect(parseServerUrl("https://")).toBeNull();
    expect(parseServerUrl("https://ho st")).toBeNull();
    // URL validates the authority after the product grammar admits it. A
    // single colon is a port separator, not proof that the port is valid.
    expect(parseServerUrl("https://api.example.com:abc")).toBeNull();
    expect(parseServerUrl("https://api.example.com:65536")).toBeNull();
    // Mangled IPv6 (two colons, unbracketed) must not slip through.
    expect(parseServerUrl("http://1:2::3:8000")).toBeNull();
  });

  it("flags bracketed non-loopback IPv6 http as insecure", () => {
    expect(parseServerUrl("http://[2001:db8::1]:8000")).toEqual({
      url: "http://[2001:db8::1]:8000",
      insecure: true,
    });
  });

  it("requires a lowercase scheme and rejects userinfo, queries and fragments", () => {
    expect(parseServerUrl("HTTP://api.example.com")).toBeNull(); // scheme is case-pinned
    expect(parseServerUrl("https://api.example.com?x=1")).toBeNull(); // query strings rejected
    expect(parseServerUrl("https://api.example.com#frag")).toBeNull(); // fragments rejected
    expect(parseServerUrl("https://user@api.example.com")).toBeNull();
    expect(parseServerUrl("https://user:pass@api.example.com")).toBeNull();
  });

  it("classifies loopback hosts exactly (with and without ports)", () => {
    for (const host of ["localhost", "127.0.0.1", "[::1]"]) {
      expect(parseServerUrl(`http://${host}:8000`)).toEqual({
        url: `http://${host}:8000`,
        insecure: false,
      });
      expect(parseServerUrl(`http://${host}`)).toEqual({
        url: `http://${host}`,
        insecure: false,
      });
    }
    // Look-alikes must NOT be treated as loopback.
    for (const host of ["localhost.evil.com", "127.0.0.2", "[::2]", "mylocalhost"]) {
      expect(parseServerUrl(`http://${host}`)?.insecure).toBe(true);
    }
  });
});

describe("detailToMessage sanitization", () => {
  it("strips whole URLs so error dialogs cannot phish", () => {
    expect(
      detailToMessage("Your account was compromised — visit https://evil.example/fix now", 400),
    ).toBe("Your account was compromised — visit now");
    // Every URL in a multi-URL message is removed entirely.
    expect(detailToMessage("go http://a.io/x and https://b.io/y now", 400)).toBe("go and now");
  });

  it("trims surrounding whitespace after control-character replacement", () => {
    expect(detailToMessage("  spaced out  ", 400)).toBe("spaced out");
  });

  it("caps hostile message length", () => {
    const message = detailToMessage("A".repeat(5_000), 400);
    expect(message.length).toBeLessThanOrEqual(202);
  });

  it("strips control characters", () => {
    const message = detailToMessage("bad\u0000\u0007blob", 422);
    expect(message).toBe("bad blob");
  });

  it("handles FastAPI validation lists and falls back to a status message", () => {
    expect(detailToMessage([{ loc: ["body"], msg: "field required" }], 422)).toBe("field required");
    expect(detailToMessage(undefined, 500)).toBe("request failed (500)");
    expect(detailToMessage({ odd: true }, 500)).toBe("request failed (500)");
  });

  it("joins multiple validation messages with '; '", () => {
    expect(
      detailToMessage([{ msg: "first problem" }, { msg: "second problem" }], 422),
    ).toBe("first problem; second problem");
  });

  it("maps malformed validation entries to a generic field message", () => {
    expect(detailToMessage([{ msg: 123 }], 422)).toBe("invalid field"); // non-string msg
    expect(detailToMessage([null], 422)).toBe("invalid field"); // null entry
    expect(detailToMessage(["raw string"], 422)).toBe("invalid field"); // not an object
  });

  it("falls back to the status message for empty details", () => {
    expect(detailToMessage([], 422)).toBe("request failed (422)");
    expect(detailToMessage("", 400)).toBe("request failed (400)"); // empty string detail
    expect(detailToMessage([{ msg: "" }], 422)).toBe("request failed (422)"); // sanitized to empty
  });

  it("keeps messages at exactly the cap and truncates one char over", () => {
    const exactly = "x".repeat(200);
    expect(detailToMessage(exactly, 400)).toBe(exactly);
    const over = detailToMessage("x".repeat(201), 400);
    expect(over).toHaveLength(201); // 200 chars + 1-char ellipsis
    expect(over.endsWith("…")).toBe(true);
  });
});

describe("detailToMessage: non-http schemes (L3)", () => {
  it("strips deep-link and other scheme URLs", () => {
    expect(detailToMessage("verify at mywallet://transfer?to=evil now", 400)).toBe("verify at now");
    expect(detailToMessage("see ftp://files.evil.example/x now", 400)).toBe("see now");
  });
});
