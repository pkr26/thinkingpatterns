/** Public wire and response-consumption contracts exercised without replacing
 * the API client. Fetch answers with native Response/ReadableStream objects. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, auth, clearSession, listEntriesWalk, sessionUsername, setSession, setSessionExpiredHandler } from "../src/api/client";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";

beforeEach(() => { resetTestState(); installSession(); setSessionExpiredHandler(null); });
afterEach(() => { clearSession(); setSessionExpiredHandler(null); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

const ORIGIN = "http://localhost:5173";
const entry = (id: string) => ({ id, client_entry_id: id, blob: "encrypted", entry_date: "2026-10-05", received_at: "2026-10-05T12:00:00Z" });
const consent = (id: string) => ({ id: id.padStart(32, "a"), therapist_id: "therapist", display_name: "River", status: "active", created_at: "2026-10-05T12:00:00Z" });

describe("real HTTP requests", () => {
  const cases: [string, () => unknown, string, string, unknown, Record<string, string>?][] = [
    ["legacy registration", () => auth.register("alice", "salt", "proof", "minimum_age_confirmed_v1"), "POST", "/auth/register", { username: "alice", salt: "salt", verifier: "proof", age_attestation: "minimum_age_confirmed_v1" }],
    ["envelope registration", () => auth.register("alice", "salt", "proof", "minimum_age_confirmed_v1", { kdfParams: { algorithm: "pbkdf2-sha256", version: 1, iterations: 600000 }, wrappedDataKeyB64: "wrapped" }), "POST", "/auth/register", { username: "alice", salt: "salt", verifier: "proof", age_attestation: "minimum_age_confirmed_v1", kdf_params: { algorithm: "pbkdf2-sha256", version: 1, iterations: 600000 }, wrapped_data_key: "wrapped" }],
    ["key envelope", () => api.keyEnvelope(), "GET", "/auth/key-envelope", undefined],
    ["entry creation", () => api.createEntry("entry_1", "sealed", "2026-10-05", 3), "POST", "/entries", { client_entry_id: "entry_1", blob: "sealed", entry_date: "2026-10-05", content_version: 3 }],
    ["entry creation without version", () => api.createEntry("entry_1", "sealed", "2026-10-05"), "POST", "/entries", { client_entry_id: "entry_1", blob: "sealed", entry_date: "2026-10-05" }],
    ["measure creation", () => api.createMeasure("measure_1", "sealed", "2026-10-05"), "POST", "/measures", { client_measure_id: "measure_1", blob: "sealed", measure_date: "2026-10-05" }],
    ["processing session", () => api.openProcessingSession("data-key"), "POST", "/processing/sessions", { data_key: "data-key" }],
    ["recompute with feedback", () => api.recompute("processing", "sealed-feedback"), "POST", "/insights/recompute", { feedback_blob: "sealed-feedback" }, { "X-Processing-Token": "processing" }],
    ["recompute without feedback", () => api.recompute("processing"), "POST", "/insights/recompute", undefined, { "X-Processing-Token": "processing" }],
    ["insights", () => api.insights(), "GET", "/insights", undefined],
    ["daily question", () => api.questionToday(), "GET", "/questions/today", undefined],
    ["step-up proof", () => api.stepUp("verifier", "account_delete"), "POST", "/account/step-up", { verifier: "verifier", action: "account_delete" }],
    ["account deletion", () => api.deleteAccount("delete-proof"), "DELETE", "/account", undefined, { "X-Step-Up-Proof": "delete-proof" }],
    ["LLM consent read", () => api.getLlmConsent(), "GET", "/account/llm-consent", undefined],
    ["LLM consent enable", () => api.setLlmConsent(true, "llm-proof"), "PUT", "/account/llm-consent", { enabled: true }, { "X-Step-Up-Proof": "llm-proof" }],
    ["LLM consent disable", () => api.setLlmConsent(false, "llm-proof"), "PUT", "/account/llm-consent", { enabled: false }, { "X-Step-Up-Proof": "llm-proof" }],
    ["credential rotation", () => api.rotateCredential("old-proof", "new-salt", "new-proof"), "PUT", "/account/credential", { verifier: "old-proof", new_salt: "new-salt", new_verifier: "new-proof" }],
    ["password envelope rotation", () => api.changePassword({ verifierB64: "old", newSaltB64: "salt", newVerifierB64: "new", wrappedDataKeyB64: "wrapped", processingToken: "processing", newKdfParams: { iterations: 600000 } }), "PUT", "/account/password", { verifier: "old", new_salt: "salt", new_verifier: "new", wrapped_data_key: "wrapped", new_kdf_params: { iterations: 600000 } }, { "X-Processing-Token": "processing" }],
    ["password rotation retaining cost", () => api.changePassword({ verifierB64: "old", newSaltB64: "salt", newVerifierB64: "new", wrappedDataKeyB64: "wrapped", processingToken: "processing" }), "PUT", "/account/password", { verifier: "old", new_salt: "salt", new_verifier: "new", wrapped_data_key: "wrapped" }, { "X-Processing-Token": "processing" }],
    ["key envelope upgrade", () => api.upgradeKeyEnvelope("wrapped", { iterations: 600000 }, "processing", "proof"), "POST", "/account/key-envelope/upgrade", { kdf_params: { iterations: 600000 }, wrapped_data_key: "wrapped" }, { "X-Processing-Token": "processing", "X-Account-Verifier": "proof" }],
    ["pairing lookup", () => api.pairingLookup("123 456"), "POST", "/consents/pairing/lookup", { code: "123 456" }],
    ["consent grant", () => api.grantConsent("123 456", "ephemeral", "wrapped", "share-proof"), "POST", "/consents", { code: "123 456", ephemeral_pub: "ephemeral", wrapped_key: "wrapped", disclosure: "v3" }, { "X-Step-Up-Proof": "share-proof" }],
    ["consent rewrap", () => api.rewrapConsent("a".repeat(32), "ephemeral", "wrapped", "share-proof"), "PUT", "/consents/" + "a".repeat(32) + "/rewrap", { ephemeral_pub: "ephemeral", wrapped_key: "wrapped" }, { "X-Step-Up-Proof": "share-proof" }],
    ["consent revocation", () => api.revokeConsent("a".repeat(32), "share-proof"), "DELETE", "/consents/" + "a".repeat(32), undefined, { "X-Step-Up-Proof": "share-proof" }],
    ["atomic data rekey", () => api.rekeyStoredData("old-session", "new-session", "proof", { operation_id: "operation", new_salt: "salt", new_verifier: "next" }), "POST", "/processing/rekey", { operation_id: "operation", new_salt: "salt", new_verifier: "next" }, { "X-Processing-Token": "old-session", "X-New-Processing-Token": "new-session", "X-Account-Verifier": "proof" }],
    ["public meta", () => auth.meta(), "GET", "/meta", undefined],
    ["authenticated meta", () => api.meta(), "GET", "/meta", undefined],
    ["salt lookup", () => auth.saltFor("alice"), "POST", "/auth/salt", { username: "alice" }],
    ["login", () => auth.login("alice", "verifier"), "POST", "/auth/login", { username: "alice", verifier: "verifier" }],
    ["transcription", () => api.transcribeAudio("audio", "audio/mp4", 23), "POST", "/audio/transcriptions", { audio_b64: "audio", mime: "audio/mp4", duration_seconds: 23 }],
    ["translation", () => api.translateText("hola", "es"), "POST", "/audio/translations", { text: "hola", source_lang: "es" }],
    ["translation without language", () => api.translateText("hello", null), "POST", "/audio/translations", { text: "hello" }],
    ["kept recording", () => api.uploadAudioAttachment("entry_1", "sealed-audio", "audio/mp4", 19), "POST", "/audio/attachments", { client_entry_id: "entry_1", blob: "sealed-audio", mime: "audio/mp4", duration_seconds: 19 }],
    ["recording read", () => api.fetchAudioAttachment("a/b ?"), "GET", "/audio/attachments/a%2Fb%20%3F", undefined],
    ["recording removal", () => api.deleteAudioAttachment("a/b ?"), "DELETE", "/audio/attachments/a%2Fb%20%3F", undefined],
    ["voice consent read", () => api.getVoiceConsent(), "GET", "/account/voice-consent", undefined],
    ["voice consent enable", () => api.setVoiceConsent(true, "voice-proof"), "PUT", "/account/voice-consent", { enabled: true }, { "X-Step-Up-Proof": "voice-proof" }],
    ["voice consent disable", () => api.setVoiceConsent(false, "voice-proof"), "PUT", "/account/voice-consent", { enabled: false }, { "X-Step-Up-Proof": "voice-proof" }],
    ["recording sharing", () => api.setShareVoice("a/b ?", true, "share-proof"), "PUT", "/consents/a%2Fb%20%3F/share-voice", { enabled: true }, { "X-Step-Up-Proof": "share-proof" }],
    ["entry read", () => api.getEntry("entry_1"), "GET", "/entries/entry_1", undefined],
    ["entry update", () => api.updateEntry("entry_1", "sealed", "2026-10-04", 3), "PUT", "/entries/entry_1", { blob: "sealed", entry_date: "2026-10-04", content_version: 3 }],
    ["entry update without version", () => api.updateEntry("entry_1", "sealed", "2026-10-04"), "PUT", "/entries/entry_1", { blob: "sealed", entry_date: "2026-10-04" }],
    ["entry removal", () => api.deleteEntry("entry_1"), "DELETE", "/entries/entry_1", undefined],
    ["export ticket", () => api.exportAccountTicket(), "POST", "/account/export-ticket", undefined],
  ];
  it.each(cases)("sends the documented %s request", async (_name, call, method, path, body, extra = {}) => {
    const answer = { result: "native-response" };
    const fetch = stubFetch(() => jsonResponse(answer));
    expect(await call()).toEqual(answer);
    expect(fetch).toHaveBeenCalledOnce();
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(ORIGIN + "/api/v1" + path);
    expect(init.method).toBe(method);
    expect(init.body === undefined ? undefined : JSON.parse(String(init.body))).toEqual(body);
    expect(init).toMatchObject({ credentials: "omit", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer" });
    expect(init.headers).toMatchObject({ "Content-Type": "application/json", ...extra });
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it.each(["/entry", "entry/", "a".repeat(65), "a\n", "", "☀"])("refuses hostile entry identifiers before dispatch (%s)", async id => {
    const fetch = stubFetch(() => jsonResponse({}));
    for (const call of [() => api.getEntry(id), () => api.updateEntry(id, "blob", "2026-10-05"), () => api.deleteEntry(id), () => api.uploadAudioAttachment(id, "blob", "audio/mp4", 2)]) {
      expect(call).toThrow("invalid entry id");
    }
    expect(fetch).not.toHaveBeenCalled();
  });

  it("keeps per-device logout alive after the caller clears its session", async () => {
    const fetch = stubFetch(async (_url, init) => { clearSession(); expect(init.signal?.aborted).toBe(false); return new Response(null, { status: 204 }); });
    expect(await api.logout()).toBeNull();
    expect(fetch.mock.calls[0]).toEqual([ORIGIN + "/api/v1/auth/logout", expect.objectContaining({ method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer token-123" } })]);
  });

  it("reports sanitized logout rejection rather than silently succeeding", async () => {
    stubFetch(() => jsonResponse({ detail: "go evilapp://danger/pay now", code: "forbidden" }, { status: 403 }));
    await expect(api.logout()).rejects.toMatchObject({ name: "ApiError", status: 403, code: "forbidden", message: "go now" });
  });

  it.each([null, false, 7, "untrusted", [], { unrelated: "data" }])("keeps malformed error envelope %j on the typed API failure surface", async body => {
    stubFetch(() => jsonResponse(body, { status: 403 }));
    await expect(auth.meta()).rejects.toMatchObject({ name: "ApiError", status: 403, message: "request failed (403)" });
    await expect(api.logout()).rejects.toMatchObject({ name: "ApiError", status: 403, message: "request failed (403)" });
    await expect(api.meta()).rejects.toMatchObject({ name: "ApiError", status: 403, message: "request failed (403)" });
  });

  it("exposes the active username and clears it with the session", () => {
    expect(sessionUsername()).toBe("tester"); clearSession(); expect(sessionUsername()).toBeNull();
  });
});

describe("pagination wire boundaries", () => {
  const resources = [
    ["entries", "X-Entries-Revision", () => api.listEntriesPage({ offset: 3, expectedRevision: "9223372036854775807" })],
    ["measures", "X-Measures-Revision", () => api.listMeasuresPage({ offset: 3, expectedRevision: "9223372036854775807" })],
    ["consents", "X-Consents-Revision", () => api.listConsentsPage({ offset: 3, expectedRevision: "9223372036854775807" })],
  ] as const;
  it.each(resources)("preserves a signed-64-bit %s revision without rounding", async (resource, header, call) => {
    const rows = [resource === "consents" ? consent("1") : entry("1")];
    const fetch = stubFetch(() => jsonResponse(rows, { headers: { [header]: "9223372036854775807", "X-Next-Offset": "4" } }));
    expect(await call()).toMatchObject({ revision: "9223372036854775807", nextOffset: 4 });
    const url = new URL(fetch.mock.calls[0]![0] as string);
    expect(url.pathname).toBe("/api/v1/" + resource);
    expect(url.searchParams.get("offset")).toBe("3");
    expect(url.searchParams.get("expected_revision")).toBe("9223372036854775807");
    expect(url.searchParams.get("limit")).toBe(resource === "consents" ? "200" : "100");
    if (resource !== "consents") expect(url.searchParams.get("page_bytes")).toBe("2097152");
  });

  it.each(["x1", "1x", "01", "1e2", "-1", "1.5", "9007199254740993"])("rejects malformed continuation %s", async value => {
    stubFetch(() => jsonResponse([entry("1")], { headers: { "X-Next-Offset": value } }));
    await expect(api.listEntriesPage()).rejects.toThrow("invalid entries continuation");
    await expect(api.listMeasuresPage()).rejects.toThrow("invalid measures continuation");
    await expect(api.listConsentsPage()).rejects.toThrow("invalid consents continuation");
  });

  it.each(["x1", "1x", "01", "-1", "9223372036854775808", "9999999999999999999", "10000000000000000000"])("rejects malformed collection revision %s", async value => {
    stubFetch(() => jsonResponse([], { headers: { "X-Entries-Revision": value, "X-Measures-Revision": value, "X-Consents-Revision": value } }));
    await expect(api.listEntriesPage()).rejects.toThrow("invalid entries snapshot revision");
    await expect(api.listMeasuresPage()).rejects.toThrow("invalid measures snapshot revision");
    await expect(api.listConsentsPage()).rejects.toThrow("invalid consents snapshot revision");
  });

  it("refuses dropped or changed pinned entry/measure revisions", async () => {
    for (const headers of [{}, { "X-Entries-Revision": "8", "X-Measures-Revision": "8" }] as Record<string, string>[]) {
      stubFetch(() => jsonResponse([], { headers }));
      await expect(api.listEntriesPage({ expectedRevision: "7" })).rejects.toThrow(/snapshot revision/);
      await expect(api.listMeasuresPage({ expectedRevision: "7" })).rejects.toThrow(/snapshot revision/);
    }
  });

  it.each([{ limit: 0 }, { limit: 1.5 }, { limit: 501 }, { offset: -1 }, { offset: 0.5 }, { offset: Number.MAX_SAFE_INTEGER + 1 }, { pageBytes: 0 }, { pageBytes: 1.5 }, { pageBytes: 2097153 }, { expectedRevision: "x7" }])("refuses invalid entry page options %j before I/O", async options => {
    const fetch = stubFetch(() => jsonResponse([]));
    await expect(api.listEntriesPage(options)).rejects.toThrow("invalid entry page request"); expect(fetch).not.toHaveBeenCalled();
  });

  it("accepts minimum entry page bounds and URL-encodes since", async () => {
    const fetch = stubFetch(() => jsonResponse([]));
    expect(await api.listEntriesPage({ limit: 1, pageBytes: 1, since: "2026-10-05 + ?", expectedRevision: undefined })).toMatchObject({ entries: [], nextOffset: null });
    const url = new URL(fetch.mock.calls[0]![0] as string);
    expect(Object.fromEntries(url.searchParams)).toEqual({ limit: "1", offset: "0", page_bytes: "1", since: "2026-10-05 + ?" });
  });

  it.each([-1, 1.5, Number.MAX_SAFE_INTEGER + 1])("refuses invalid measure offset %s", async offset => {
    const fetch = stubFetch(() => jsonResponse([]));
    await expect(api.listMeasuresPage({ offset })).rejects.toThrow("invalid measure page request"); expect(fetch).not.toHaveBeenCalled();
  });

  it.each([-1, 1.5, 1001, Number.MAX_SAFE_INTEGER + 1])("refuses invalid consent offset %s", async offset => {
    const fetch = stubFetch(() => jsonResponse([]));
    await expect(api.listConsentsPage({ offset })).rejects.toThrow("invalid consent page request"); expect(fetch).not.toHaveBeenCalled();
  });

  it("permits the last consent page offset and legacy full-page continuation", async () => {
    const rows = Array.from({ length: 200 }, (_, i) => consent(String(i)));
    const fetch = stubFetch(() => jsonResponse(rows));
    expect(await api.listConsentsPage({ offset: 1000 })).toEqual({ consents: rows, nextOffset: 1200, revision: undefined });
    expect(new URL(fetch.mock.calls[0]![0] as string).searchParams.get("offset")).toBe("1000");
  });

  it("refuses an oversized consent page and non-array pages", async () => {
    stubFetch(() => jsonResponse(Array.from({ length: 201 }, (_, i) => consent(String(i)))));
    await expect(api.listConsentsPage()).rejects.toThrow("invalid consents page");
    stubFetch(() => jsonResponse({ rows: [] }));
    await expect(api.listConsentsPage()).rejects.toThrow("invalid consents page");
    await expect(api.listEntriesPage()).rejects.toThrow("invalid entries page");
    await expect(api.listMeasuresPage()).rejects.toThrow("invalid measures page");
  });

  it("requires current ownership before an entry walk sends its first request", async () => {
    const fetch = stubFetch(() => jsonResponse([]));
    await expect(listEntriesWalk(undefined, () => false)).rejects.toThrow("session ended"); expect(fetch).not.toHaveBeenCalled();
  });

  it("requires current ownership again after a page settles", async () => {
    let current = true;
    const fetch = stubFetch(() => { current = false; return jsonResponse([entry("1")]); });
    await expect(listEntriesWalk(undefined, () => current)).rejects.toThrow("session ended"); expect(fetch).toHaveBeenCalledOnce();
  });

  for (const startMode of ["legacy", "snapshot"] as const) {
    it(`restarts rather than mixing consent pages when ${startMode} protocol changes`, async () => {
      let call = 0;
      const fetch = stubFetch(() => {
        ++call;
        if (call === 1) return jsonResponse([consent("old")], { headers: { "X-Next-Offset": "1", ...(startMode === "snapshot" ? { "X-Consents-Revision": "7" } : {}) } });
        if (call === 2) return jsonResponse([consent("mixed")], { headers: startMode === "legacy" ? { "X-Consents-Revision": "7" } : {} });
        return jsonResponse([consent("fresh")], { headers: { "X-Consents-Revision": "8" } });
      });
      expect(await api.listConsents()).toEqual([consent("fresh")]); expect(fetch).toHaveBeenCalledTimes(3);
      expect(new URL(fetch.mock.calls[2]![0] as string).searchParams.get("offset")).toBe("0");
    });
  }

  it.each([[409, "collection_changed", 3], [409, "version_conflict", 1], [403, "collection_changed", 1]] as const)("bounds consent retries for status %s / %s", async (status, code, calls) => {
    const fetch = stubFetch(() => jsonResponse({ detail: "changed", code }, { status }));
    await expect(api.listConsents()).rejects.toMatchObject({ status, code }); expect(fetch).toHaveBeenCalledTimes(calls);
  });

  it("handles the opaque access-log cursor and refuses malformed row bodies", async () => {
    const rows = [{ at: "2026-10-05", action: "read", actor: "therapist" }];
    const fetch = stubFetch(() => jsonResponse(rows, { headers: { "X-Next-Cursor": "next/+ ?" } }));
    expect(await api.accessLogPage("previous/+ ?")).toEqual({ rows, nextCursor: "next/+ ?" });
    expect(new URL(fetch.mock.calls[0]![0] as string).searchParams.get("cursor")).toBe("previous/+ ?");
    stubFetch(() => jsonResponse({ rows }, { headers: { "X-Next-Cursor": " " } }));
    expect(await api.accessLogPage()).toEqual({ rows: [], nextCursor: null });
  });
});

describe("authenticated stream consumption", () => {
  it("preserves export status, headers, origin and bytes through the guarded reader", async () => {
    const response = new Response("sealed export", { status: 200, statusText: "Export ready", headers: { "Content-Type": "application/json", "X-Export-Format": "sealed-v1" } });
    Object.defineProperty(response, "url", { value: ORIGIN + "/api/v1/account/export" });
    const fetch = stubFetch(() => response);
    const exported = await api.exportAccountRaw();
    expect(exported.status).toBe(200); expect(exported.statusText).toBe("Export ready");
    expect(exported.headers.get("X-Export-Format")).toBe("sealed-v1"); expect(exported.url).toBe(response.url);
    expect(await exported.text()).toBe("sealed export");
    expect(fetch.mock.calls[0]).toEqual([ORIGIN + "/api/v1/account/export", expect.objectContaining({ method: "GET", headers: { Authorization: "Bearer token-123" } })]);
  });

  it("cancels the underlying export stream with the consumer's reason", async () => {
    const cancelled = vi.fn();
    stubFetch(() => new Response(new ReadableStream({ cancel: cancelled })));
    const exported = await api.exportAccountRaw();
    await exported.body!.cancel("download abandoned"); expect(cancelled).toHaveBeenCalledWith("download abandoned");
  });

  it("propagates a source-reader failure and cancels the source", async () => {
    const cancelled = vi.fn();
    const failure = new Error("transport interrupted");
    const source = new ReadableStream<Uint8Array>({ pull() { throw failure; }, cancel: cancelled });
    stubFetch(() => new Response(source));
    const exported = await api.exportAccountRaw();
    await expect(exported.body!.getReader().read()).rejects.toBe(failure);
  });

  it("rejects an ordinary response beyond the 16 MiB transport limit", async () => {
    stubFetch(() => new Response(new Uint8Array(16 * 1024 * 1024 + 1)));
    await expect(api.insights()).rejects.toThrow("safe size limit");
  });

  it("permits the documented 100 MiB export bound and rejects one extra byte", async () => {
    for (const excess of [0, 1]) {
      let sent = 0; const chunk = new Uint8Array(10 * 1024 * 1024);
      const source = new ReadableStream<Uint8Array>({ pull(target) { if (sent++ < 10) target.enqueue(chunk); else if (excess && sent === 11) target.enqueue(new Uint8Array(1)); else target.close(); } });
      stubFetch(() => new Response(source));
      const exported = await api.exportAccountRaw(); const reader = exported.body!.getReader();
      const consume = async () => { let bytes = 0; for (;;) { const row = await reader.read(); if (row.done) return bytes; bytes += row.value.byteLength; } };
      if (excess) await expect(consume()).rejects.toThrow("safe size limit");
      else expect(await consume()).toBe(100 * 1024 * 1024);
    }
  });

  it.each([401, 410] as const)("reports export session death once with complete context (%s)", async status => {
    const expired = vi.fn(); setSessionExpiredHandler(expired);
    stubFetch(() => jsonResponse({ detail: "account unavailable", code: status === 401 ? "unauthorized" : "account_deleted" }, { status }));
    for (let i = 0; i < 2; i++) await expect(api.exportAccountRaw()).rejects.toMatchObject({ status, code: status === 401 ? "unauthorized" : "account_deleted", message: status === 401 ? "session ended" : "account unavailable" });
    expect(expired).toHaveBeenCalledOnce();
    expect(expired.mock.calls[0]![1]).toEqual({ userId: "user-1", origin: ORIGIN, accountDeleted: status === 410 });
    installSession("second-user");
    await expect(api.exportAccountRaw()).rejects.toMatchObject({ status });
    expect(expired).toHaveBeenCalledTimes(2); expect(expired.mock.calls[1]![1].userId).toBe("second-user");
  });

  it("does not return protected content after a session replacement during fetch", async () => {
    stubFetch(() => { setSession("replacement-token", "replacement", "other"); return jsonResponse({ blob: "protected" }); });
    await expect(api.insights()).rejects.toThrow("session ended");
    stubFetch(() => { setSession("third-token", "third", "third"); return jsonResponse({ blob: "protected" }); });
    await expect(api.exportAccountRaw()).rejects.toThrow("session ended");
  });
});
