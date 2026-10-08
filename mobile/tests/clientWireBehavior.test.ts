import { runTestControl } from "./helpers/testControl";
/** Real mobile client requests and native Response objects; no client mock. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { api, setUnauthorizedHandler } from "../src/api/client";
import { __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";

const ORIGIN = "http://localhost:8000";
const USER = "a".repeat(32);
const params = { algorithm: "pbkdf2-sha256" as const, version: 1, iterations: 600000 };
function response(body: unknown, status = 200, headers: Record<string, string> = {}) {
  const result = new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
  Object.defineProperty(result, "url", { value: ORIGIN + "/api/v1/meta" });
  return result;
}
function fetchWith(handler: (url: string, init: RequestInit) => Response | Promise<Response>) {
  const fetch = vi.fn(handler); vi.stubGlobal("fetch", fetch); return fetch;
}
beforeEach(async () => {
  storage.__reset(); runTestControl(__resetLocalKeyLifecycleForTests); setUnauthorizedHandler(null);
  await api.setSession("token-123", USER, "tester");
});
afterEach(async () => { await api.clearSession(); setUnauthorizedHandler(null); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
const row = (id: string) => ({ id, client_entry_id: id, blob: "sealed", entry_date: "2026-10-05", received_at: "2026-10-05T12:00:00Z" });

describe("mobile wire requests", () => {
  const cases: [string, () => unknown, string, string, unknown, Record<string, string>?, boolean?][] = [
    ["legacy registration", () => api.register("alice", "salt", "proof", "minimum_age_confirmed_v1"), "POST", "/auth/register", { username: "alice", salt: "salt", verifier: "proof", age_attestation: "minimum_age_confirmed_v1" }],
    ["envelope registration", () => api.register("alice", "salt", "proof", "minimum_age_confirmed_v1", params, "wrapped"), "POST", "/auth/register", { username: "alice", salt: "salt", verifier: "proof", age_attestation: "minimum_age_confirmed_v1", kdf_params: params, wrapped_data_key: "wrapped" }],
    ["login", () => api.login("alice", "proof"), "POST", "/auth/login", { username: "alice", verifier: "proof" }, {}, false],
    ["key envelope", () => api.keyEnvelope(), "GET", "/auth/key-envelope", undefined],
    ["recovery status", () => api.recoveryStatus(), "GET", "/account/recovery", undefined],
    ["recovery enrollment", () => api.setupRecoveryKit("password-proof", "recovery-proof", "wrapped", "v2"), "PUT", "/account/recovery", { password_verifier: "password-proof", verifier: "recovery-proof", wrapped_key: "wrapped", scheme: "v2" }],
    ["recovery removal", () => api.removeRecoveryKit("password-proof"), "DELETE", "/account/recovery", undefined, { verifier: "password-proof" }],
    ["recovery login", () => api.recoverLogin("alice", "recovery-proof", "v2"), "POST", "/auth/recover", { username: "alice", verifier: "recovery-proof", scheme: "v2" }, {}, false],
    ["recovery password reset", () => api.resetPasswordWithRecovery("recovery-proof", { new_salt: "salt", new_verifier: "proof", new_kdf_params: params, wrapped_data_key: "wrapped" }, "processing"), "PUT", "/account/recovery/password", { proof: "recovery-proof", new_salt: "salt", new_verifier: "proof", new_kdf_params: params, wrapped_data_key: "wrapped" }, { "X-Processing-Token": "processing" }],
    ["entry creation", () => api.createEntry("entry_1", "sealed", "2026-10-05", 3), "POST", "/entries", { client_entry_id: "entry_1", blob: "sealed", entry_date: "2026-10-05", content_version: 3 }],
    ["entry creation without version", () => api.createEntry("entry_1", "sealed", "2026-10-05"), "POST", "/entries", { client_entry_id: "entry_1", blob: "sealed", entry_date: "2026-10-05" }],
    ["measure creation", () => api.createMeasure("measure_1", "sealed", "2026-10-05"), "POST", "/measures", { client_measure_id: "measure_1", blob: "sealed", measure_date: "2026-10-05" }],
    ["entry read", () => api.getEntry("entry_1"), "GET", "/entries/entry_1", undefined],
    ["entry removal", () => api.deleteEntry("entry_1"), "DELETE", "/entries/entry_1", undefined],
    ["processing session", () => api.openProcessingSession("data-key"), "POST", "/processing/sessions", { data_key: "data-key" }],
    ["recompute with feedback", () => api.recompute("processing", "sealed-feedback"), "POST", "/insights/recompute", { feedback_blob: "sealed-feedback" }, { "X-Processing-Token": "processing" }],
    ["recompute without feedback", () => api.recompute("processing"), "POST", "/insights/recompute", undefined, { "X-Processing-Token": "processing" }],
    ["insights", () => api.insights(), "GET", "/insights", undefined],
    ["daily question", () => api.questionToday(), "GET", "/questions/today", undefined],
    ["account export", () => api.exportAccount(), "GET", "/account/export", undefined],
    ["account deletion", () => api.deleteAccount("delete-proof"), "DELETE", "/account", undefined, { "X-Account-Verifier": "delete-proof" }],
    ["LLM consent read", () => api.getLlmConsent(), "GET", "/account/llm-consent", undefined],
    ["LLM consent enable", () => api.setLlmConsent(true, "llm-proof"), "PUT", "/account/llm-consent", { enabled: true, verifier: "llm-proof" }],
    ["LLM consent disable", () => api.setLlmConsent(false, "llm-proof"), "PUT", "/account/llm-consent", { enabled: false, verifier: "llm-proof" }],
    ["credential rotation", () => api.rotateCredential("old-proof", "new-salt", "new-proof"), "PUT", "/account/credential", { verifier: "old-proof", new_salt: "new-salt", new_verifier: "new-proof" }],
    ["password envelope rotation", () => api.changePassword("old", "salt", "new", "wrapped", "processing", params), "PUT", "/account/password", { verifier: "old", new_salt: "salt", new_verifier: "new", wrapped_data_key: "wrapped", new_kdf_params: params }, { "X-Processing-Token": "processing" }],
    ["password rotation retaining cost", () => api.changePassword("old", "salt", "new", "wrapped", "processing"), "PUT", "/account/password", { verifier: "old", new_salt: "salt", new_verifier: "new", wrapped_data_key: "wrapped" }, { "X-Processing-Token": "processing" }],
    ["key envelope upgrade", () => api.upgradeKeyEnvelope(params, "wrapped", "processing", "proof"), "POST", "/account/key-envelope/upgrade", { kdf_params: params, wrapped_data_key: "wrapped" }, { "X-Processing-Token": "processing", "X-Account-Verifier": "proof" }],
    ["pairing lookup", () => api.pairingLookup("123 456"), "POST", "/consents/pairing/lookup", { code: "123 456" }],
    ["consent grant", () => api.grantConsent("123 456", "ephemeral", "wrapped", "share-proof"), "POST", "/consents", { code: "123 456", ephemeral_pub: "ephemeral", wrapped_key: "wrapped", disclosure: "v3" }, { "X-Account-Verifier": "share-proof" }],
    ["consent rewrap", () => api.rewrapConsent("a".repeat(32), "ephemeral", "wrapped", "share-proof"), "PUT", "/consents/" + "a".repeat(32) + "/rewrap", { ephemeral_pub: "ephemeral", wrapped_key: "wrapped" }, { "X-Account-Verifier": "share-proof" }],
    ["consent revocation", () => api.revokeConsent("a".repeat(32), "share-proof"), "DELETE", "/consents/" + "a".repeat(32), undefined, { "X-Account-Verifier": "share-proof" }],
    ["atomic data rekey", () => api.rekeyStoredData("old-session", "new-session", "proof", { operation_id: "operation", new_salt: "salt", new_verifier: "next", consent_wraps: [] }), "POST", "/processing/rekey", { operation_id: "operation", new_salt: "salt", new_verifier: "next", consent_wraps: [] }, { "X-Processing-Token": "old-session", "X-New-Processing-Token": "new-session", "X-Account-Verifier": "proof" }],
    ["meta", () => api.meta(), "GET", "/meta", undefined],
    ["salt", () => api.saltFor("alice"), "POST", "/auth/salt", { username: "alice" }],
    ["transcription", () => api.transcribeAudio("audio", "audio/mp4", 23), "POST", "/audio/transcriptions", { audio_b64: "audio", mime: "audio/mp4", duration_seconds: 23 }],
    ["translation", () => api.translateText("hola", "es"), "POST", "/audio/translations", { text: "hola", source_lang: "es" }],
    ["translation without language", () => api.translateText("hello", null), "POST", "/audio/translations", { text: "hello" }],
    ["kept recording", () => api.uploadAudioAttachment("entry_1", "sealed-audio", "audio/mp4", 19), "POST", "/audio/attachments", { client_entry_id: "entry_1", blob: "sealed-audio", mime: "audio/mp4", duration_seconds: 19 }],
    ["recording read", () => api.fetchAudioAttachment("a/b ?"), "GET", "/audio/attachments/a%2Fb%20%3F", undefined],
    ["recording removal", () => api.deleteAudioAttachment("a/b ?"), "DELETE", "/audio/attachments/a%2Fb%20%3F", undefined],
    ["voice consent read", () => api.getVoiceConsent(), "GET", "/account/voice-consent", undefined],
    ["voice consent enable", () => api.setVoiceConsent(true, "voice-verifier"), "PUT", "/account/voice-consent", { enabled: true, verifier: "voice-verifier" }],
    ["voice consent disable", () => api.setVoiceConsent(false, "voice-verifier"), "PUT", "/account/voice-consent", { enabled: false, verifier: "voice-verifier" }],
    ["recording sharing", () => api.setShareVoice("a/b ?", true, "share-verifier"), "PUT", "/consents/a%2Fb%20%3F/share-voice", { enabled: true }, { "X-Account-Verifier": "share-verifier" }],
    ["entry update", () => api.updateEntry("entry_1", "sealed", "2026-10-04", 3), "PUT", "/entries/entry_1", { blob: "sealed", entry_date: "2026-10-04", content_version: 3 }],
    ["entry update without version", () => api.updateEntry("entry_1", "sealed", "2026-10-04"), "PUT", "/entries/entry_1", { blob: "sealed", entry_date: "2026-10-04" }],
    ["entry removal", () => api.deleteEntry("entry_1"), "DELETE", "/entries/entry_1", undefined],
    ["logout", () => api.logout(), "POST", "/auth/logout", undefined],
  ];
  it.each(cases)("sends the documented %s request", async (_name, call, method, path, body, extra = {}, bearer = true) => {
    const answer = { result: "native-response" }; const fetch = fetchWith(() => response(answer));
    expect(await call()).toEqual(answer); expect(fetch).toHaveBeenCalledOnce();
    const [url, init] = fetch.mock.calls[0]!;
    expect(url).toBe(ORIGIN + "/api/v1" + path); expect(init.method).toBe(method);
    expect(init.body === undefined ? undefined : JSON.parse(String(init.body))).toEqual(body);
    expect(init.headers).toMatchObject({ "Content-Type": "application/json", ...extra });
    expect(new Headers(init.headers).get("Authorization")).toBe(bearer ? "Bearer token-123" : null);
    expect(init.redirect).toBe("error");
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it.each([null, false, 7, "untrusted", [], { unrelated: "data" }])("keeps malformed error envelope %j on the typed failure surface", async body => {
    fetchWith(() => response(body, 403));
    await expect(api.meta()).rejects.toMatchObject({ name: "ApiError", status: 403, message: "request failed (403)" });
    await expect(api.logout()).rejects.toMatchObject({ name: "ApiError", status: 403, message: "request failed (403)" });
  });

  it("preserves a successful null response and the explicit no-content contract", async () => {
    fetchWith(() => response(null)); expect(await api.meta()).toBeNull();
    fetchWith(() => new Response(null, { status: 204 })); expect(await api.logout()).toBeNull();
  });
});

describe("mobile collection wire boundaries", () => {
  const resources = [
    ["entries", "X-Entries-Revision", () => api.listEntriesPage({ offset: 3, expectedRevision: "9223372036854775807" })],
    ["measures", "X-Measures-Revision", () => api.listMeasuresPage({ offset: 3, expectedRevision: "9223372036854775807" })],
    ["consents", "X-Consents-Revision", () => api.listConsentsPage({ offset: 3, expectedRevision: "9223372036854775807" })],
  ] as const;
  it.each(resources)("preserves signed-64-bit %s revisions without rounding", async (resource, header, call) => {
    const fetch = fetchWith(() => response([row("1")], 200, { [header]: "9223372036854775807", "X-Next-Offset": "4" }));
    expect(await call()).toMatchObject({ revision: "9223372036854775807", nextOffset: 4 });
    const url = new URL(fetch.mock.calls[0]![0]);
    expect(url.pathname).toBe("/api/v1/" + resource); expect(url.searchParams.get("offset")).toBe("3");
    expect(url.searchParams.get("expected_revision")).toBe("9223372036854775807");
    expect(url.searchParams.get("limit")).toBe(resource === "consents" ? "200" : "100");
  });

  it.each(["x1", "1x", "01", "1e2", "-1", "1.5", "9007199254740993"])("rejects malformed continuation %s", async value => {
    fetchWith(() => response([row("1")], 200, { "X-Next-Offset": value }));
    for (const call of [() => api.listEntriesPage(), () => api.listMeasuresPage(), () => api.listConsentsPage()]) await expect(call()).rejects.toMatchObject({ name: "ApiError", status: 0 });
  });

  it.each(["x1", "1x", "01", "-1", "9223372036854775808", "9999999999999999999", "10000000000000000000"])("rejects malformed revision %s", async value => {
    fetchWith(() => response([], 200, { "X-Entries-Revision": value, "X-Measures-Revision": value, "X-Consents-Revision": value }));
    for (const call of [() => api.listEntriesPage(), () => api.listMeasuresPage(), () => api.listConsentsPage()]) await expect(call()).rejects.toMatchObject({ name: "ApiError", status: 0 });
  });

  it("refuses dropped or changed pinned revisions", async () => {
    for (const headers of [{}, { "X-Entries-Revision": "8", "X-Measures-Revision": "8", "X-Consents-Revision": "8" }] as Record<string, string>[]) {
      fetchWith(() => response([], 200, headers));
      for (const call of [() => api.listEntriesPage({ expectedRevision: "7" }), () => api.listMeasuresPage({ expectedRevision: "7" }), () => api.listConsentsPage({ expectedRevision: "7" })]) await expect(call()).rejects.toMatchObject({ status: 409, code: "collection_changed" });
    }
  });

  it.each([{ limit: 0 }, { limit: 1.5 }, { limit: 501 }, { offset: -1 }, { offset: 0.5 }, { offset: Number.MAX_SAFE_INTEGER + 1 }, { pageBytes: 0 }, { pageBytes: 1.5 }, { pageBytes: 2097153 }, { expectedRevision: "x7" }])("refuses invalid entry options %j before I/O", async options => {
    const fetch = fetchWith(() => response([])); await expect(api.listEntriesPage(options)).rejects.toThrow("invalid entry page request"); expect(fetch).not.toHaveBeenCalled();
  });

  it("accepts minimum entry bounds and preserves both date filters", async () => {
    const fetch = fetchWith(() => response([]));
    expect(await api.listEntriesPage({ limit: 1, pageBytes: 1, since: "2026-10-01 + ?", until: "2026-10-05 + ?" })).toMatchObject({ entries: [], nextOffset: null, revision: null });
    expect(Object.fromEntries(new URL(fetch.mock.calls[0]![0]).searchParams)).toEqual({ limit: "1", offset: "0", page_bytes: "1", since: "2026-10-01 + ?", until: "2026-10-05 + ?" });
  });

  it.each([-1, 1.5, Number.MAX_SAFE_INTEGER + 1])("refuses invalid measure offset %s", async offset => {
    const fetch = fetchWith(() => response([])); await expect(api.listMeasuresPage({ offset })).rejects.toMatchObject({ name: "ApiError", status: 0 }); expect(fetch).not.toHaveBeenCalled();
  });

  it.each([-1, 1.5, 1001, Number.MAX_SAFE_INTEGER + 1])("refuses invalid consent offset %s", async offset => {
    const fetch = fetchWith(() => response([])); await expect(api.listConsentsPage({ offset })).rejects.toMatchObject({ name: "ApiError", status: 0 }); expect(fetch).not.toHaveBeenCalled();
  });

  it("refuses non-array pages and impossible empty-page continuations", async () => {
    for (const body of [{ rows: [] }, []]) {
      fetchWith(() => response(body, 200, { "X-Next-Offset": "1" }));
      for (const call of [() => api.listEntriesPage(), () => api.listMeasuresPage(), () => api.listConsentsPage()]) await expect(call()).rejects.toMatchObject({ name: "ApiError", status: 0 });
    }
  });
});
