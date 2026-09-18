import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { api, DEFAULT_BASE_URL, setBaseUrl, setOriginChangeHandler } from "../src/api/client";

const response = (body: unknown, url: string) => {
  const result = new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  Object.defineProperty(result, "url", { value: url });
  return result;
};

beforeEach(() => {
  storage.__reset();
  setOriginChangeHandler(null);
  vi.stubGlobal("fetch", vi.fn(async () => response({}, DEFAULT_BASE_URL)));
});

afterEach(() => {
  setOriginChangeHandler(null);
  vi.unstubAllGlobals();
});

describe("API-origin changes", () => {
  it("rejects cleartext non-loopback URLs even if an obsolete caller passes allowInsecure", async () => {
    await expect(setBaseUrl("http://journal.example.test", { allowInsecure: true })).resolves.toMatch(/plain HTTP/);
    expect(await api.isLoggedIn()).toBe(false);
  });

  it("allows loopback HTTP for local development without granting it to look-alike hosts", async () => {
    expect(await setBaseUrl("http://127.0.0.1:8000")).toBeNull();
    expect(await setBaseUrl("http://localhost.evil.test:8000")).toMatch(/plain HTTP/);
  });

  it("enforces the HTTPS boundary again at send time if persisted settings are tampered", async () => {
    await api.setSession("live-token", "user-1", "alice");
    await storage.setItem("@mindpattern/base_url", "http://remote.example.test:8000");
    await expect(api.meta()).rejects.toMatchObject({ status: 0 });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("erases session material and locks the app hook before a new origin is persisted", async () => {
    await api.setSession("live-token", "user-1", "alice");
    const transitions: string[] = [];
    setOriginChangeHandler(() => transitions.push("locked"));

    await expect(setBaseUrl("https://remote.example.test")).resolves.toBeNull();
    expect(transitions).toEqual(["locked"]);
    expect(await api.isLoggedIn()).toBe(false);

    vi.mocked(fetch).mockResolvedValue(response({}, "https://remote.example.test/api/v1/meta"));
    await api.meta();
    const [, options] = vi.mocked(fetch).mock.calls[0]!;
    expect((options?.headers as Record<string, string>).Authorization).toBeUndefined();
    expect(options?.redirect).toBe("error");
  });

  it("retains a session for a path-only change on the same origin", async () => {
    await setBaseUrl("https://same.example.test");
    await api.setSession("live-token", "user-1");
    expect(await setBaseUrl("https://same.example.test/base-path")).toBeNull();
    expect(await api.isLoggedIn()).toBe(true);
  });
});
