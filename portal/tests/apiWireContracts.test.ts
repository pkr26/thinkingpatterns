import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, auth, clearSession, setSession } from "../src/api";
const base = "https://clinic.example.com";
const json = (body: unknown, status = 200, headers: HeadersInit = {}) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
beforeEach(() => { clearSession(); setSession("protected-bearer", base); });
afterEach(() => { clearSession(); vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers(); });
const custody = { verifier: "proof", operation_id: "atomic-1", expected_custody_version: 0, custody_version: 1, notes_keyring_blob: "sealed-custody" };
const credential = { ...custody, new_salt: "new-salt", new_verifier: "new-proof", wrap_pub_key: "public-identity", wrap_key_blob: "sealed-identity" };
const rekey = [{ note_id: "note-1", blob: "new-note", base_version: 3, revision_blobs: [{ revision_id: "revision-1", blob: "old-note" }] }];
const wireCases = [
  { name: "clinical account metadata", invoke: () => api.me(), method: "GET", path: "/therapist/me" },
  { name: "new clinical note", invoke: () => api.createNote("patient /1", { client_note_id: "client-note", blob: "sealed-note", pattern_pid: null }), method: "POST", path: "/therapist/patients/patient%20%2F1/notes", body: { client_note_id: "client-note", blob: "sealed-note", pattern_pid: null } },
  { name: "delete clinical note", invoke: () => api.deleteNote("note /1"), method: "DELETE", path: "/therapist/notes/note%20%2F1" },
  { name: "new one-time pairing code", invoke: () => api.newPairingCode(), method: "POST", path: "/therapist/pairing-codes" },
  { name: "install note custody", invoke: () => api.installNotesCustody(custody), method: "PUT", path: "/therapist/custody", body: custody },
  { name: "atomic password change", invoke: () => api.changePasswordAtomic(credential), method: "PUT", path: "/therapist/password", body: credential },
  { name: "access history", invoke: () => api.accessLog(), method: "GET", path: "/therapist/access-log?limit=100" },
  { name: "recorded audio", invoke: () => api.patientAudio("patient /1", "audio /2"), method: "GET", path: "/therapist/patients/patient%20%2F1/audio/audio%20%2F2" },
  { name: "note revisions", invoke: () => api.noteRevisions("note /1"), method: "GET", path: "/therapist/notes/note%20%2F1/revisions" },
  { name: "old note rekey", invoke: () => api.rekeyNotes("proof", rekey), method: "PUT", path: "/therapist/notes/rekey", body: { items: rekey }, extra: { "X-Account-Verifier": "proof" } },
  { name: "custody-bound note rekey", invoke: () => api.rekeyNotes("proof", rekey, 4), method: "PUT", path: "/therapist/notes/rekey", body: { items: rekey, custody_version: 4 }, extra: { "X-Account-Verifier": "proof" } },
  { name: "custody-bound edit", invoke: () => api.updateNote("note /1", "changed-note", 3, 4), method: "PATCH", path: "/therapist/notes/note%20%2F1", body: { blob: "changed-note", base_version: 3, custody_version: 4 } },
  { name: "unbound key rotation", invoke: () => api.rotateWrapKey("proof", "public-identity", "sealed-identity"), method: "PUT", path: "/therapist/wrap-key", body: { wrap_pub_key: "public-identity", wrap_key_blob: "sealed-identity" }, extra: { "X-Account-Verifier": "proof" } },
  { name: "custody-bound key rotation", invoke: () => api.rotateWrapKey("proof", "public-identity", "sealed-identity", 4), method: "PUT", path: "/therapist/wrap-key", body: { wrap_pub_key: "public-identity", wrap_key_blob: "sealed-identity", expected_custody_version: 4 }, extra: { "X-Account-Verifier": "proof" } },
  { name: "authenticator setup", invoke: () => api.totpSetup("proof"), method: "POST", path: "/account/totp/setup", body: { verifier: "proof" } },
  { name: "authenticator enable", invoke: () => api.totpEnable("proof", "123456"), method: "POST", path: "/account/totp/enable", body: { verifier: "proof", code: "123456" } },
  { name: "authenticator disable", invoke: () => api.totpDisable("proof", "654321"), method: "POST", path: "/account/totp/disable", body: { verifier: "proof", code: "654321" } },
];
it.each(wireCases)("preserves the server request contract for $name", async ({ invoke, method, path, body, extra }) => {
  vi.stubGlobal("fetch", vi.fn(async () => json({ acknowledged: "contract-response" })));
  await expect(invoke()).resolves.toEqual({ acknowledged: "contract-response" });
  expect(fetch).toHaveBeenCalledTimes(1);
  const [url, init] = vi.mocked(fetch).mock.calls[0]!;
  expect(url).toBe(base + "/api/v1" + path);
  expect(init).toMatchObject({ method, headers: { "Content-Type": "application/json", Authorization: "Bearer protected-bearer", ...extra }, redirect: "error", credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer" });
  expect(init!.body).toBe(body === undefined ? undefined : JSON.stringify(body));
});

it.each([
  { name: "public server metadata", invoke: () => auth.meta(base), method: "GET", path: "/meta", body: undefined },
  { name: "public account salt", invoke: () => auth.saltFor(base, "drportal"), method: "POST", path: "/auth/salt", body: { username: "drportal" } },
  { name: "clinician enrollment", invoke: () => auth.registerTherapist(base, { username: "drportal", salt: "salt", verifier: "proof", display_name: "Dr. Portal", wrap_pub_key: "public", wrap_key_blob: "sealed", age_attestation: "minimum_age_confirmed_v1" }), method: "POST", path: "/therapist/register", body: { username: "drportal", salt: "salt", verifier: "proof", display_name: "Dr. Portal", wrap_pub_key: "public", wrap_key_blob: "sealed", age_attestation: "minimum_age_confirmed_v1" } },
])("preserves unauthenticated transport for $name", async ({invoke,method,path,body}) => {
  vi.stubGlobal("fetch", vi.fn(async () => json({ acknowledged: "contract-response" })));
  await expect(invoke()).resolves.toEqual({ acknowledged: "contract-response" });
  const [url, init] = vi.mocked(fetch).mock.calls[0]!;
  expect(url).toBe(base + "/api/v1" + path);
  expect(init).toMatchObject({ method, headers: { "Content-Type": "application/json" }, redirect: "error", credentials: "omit" });
  expect(init!.body).toBe(body === undefined ? undefined : JSON.stringify(body));
});

it.each([
  { name: "measures", invoke: () => api.patientMeasures("patient /1"), path: "/therapist/patients/patient%20%2F1/measures?limit=100&page_bytes=2097152" },
  { name: "journal evidence", invoke: () => api.patientEntries("patient /1"), path: "/therapist/patients/patient%20%2F1/entries?limit=25&page_bytes=2097152" },
  { name: "clinical notes", invoke: () => api.notes("patient /1"), path: "/therapist/patients/patient%20%2F1/notes?limit=100&page_bytes=2097152" },
])("uses the exact authenticated GET contract for $name", async ({invoke,path}) => {
  vi.stubGlobal("fetch", vi.fn(async () => json([])));
  await invoke();
  const [url,init] = vi.mocked(fetch).mock.calls[0]!;
  expect(url).toBe(base + "/api/v1" + path);
  expect(init).toMatchObject({ method: "GET", headers: { "Content-Type": "application/json", Authorization: "Bearer protected-bearer" } });
  expect(init!.body).toBeUndefined();
});

it("uses the clinical insights endpoint and preserves its validated generation", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => json({ phase: "baseline", active_days: 0, streak: 0, days_remaining: 30, blob: null, state_seq: 12 })));
  await expect(api.patientInsights("patient /1")).resolves.toEqual({ phase: "baseline", active_days: 0, streak: 0, days_remaining: 30, blob: null, state_seq: 12 });
  const [url,init] = vi.mocked(fetch).mock.calls[0]!;
  expect(url).toBe(base + "/api/v1/therapist/patients/patient%20%2F1/insights");
  expect(init!.method).toBe("GET");
});

it.each([null, {}, Array(101).fill({ client_measure_id: "measure" })])("refuses malformed or oversized measure page %j", async payload => {
  vi.stubGlobal("fetch", vi.fn(async () => json(payload)));
  await expect(api.patientMeasures("patient")).rejects.toMatchObject({ message: "server returned an invalid measures page" });
});

it("completes a real headerless legacy caseload continuation without inventing a snapshot token", async () => {
  const rows = Array.from({length:200},(_,index)=>({user_id:`patient-${index}`,username:`patient${index}`,status:"active",granted_at:"2026-09-01",revoked_at:null,ephemeral_pub:null,wrapped_key:null}));
  vi.stubGlobal("fetch", vi.fn(async url => Number(new URL(String(url)).searchParams.get("offset")) > 0 ? json([]) : json(rows)));
  await expect(api.patients()).resolves.toEqual(rows);
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(vi.mocked(fetch).mock.calls.map(([url])=>new URL(String(url)).searchParams.get("expected_revision"))).toEqual([null,null]);
});

it("names the patient resource when rejecting a malformed legacy continuation header", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => json([],200,{"X-Next-Offset":"not-a-cursor"})));
  await expect(api.patientsPage()).rejects.toMatchObject({ message: "server returned an invalid patients continuation" });
});
it.each([undefined, "123456"])("includes optional MFA proof only when supplied: %s", async code => {
  vi.stubGlobal("fetch", vi.fn(async () => json({ token: "issued-bearer" })));
  await auth.login(base, "drportal", "proof", code);
  const [url, init] = vi.mocked(fetch).mock.calls[0]!;
  expect(url).toBe(base + "/api/v1/auth/login");
  expect(init!.method).toBe("POST");
  expect(JSON.parse(init!.body as string)).toEqual(code === undefined ? { username: "drportal", verifier: "proof" } : { username: "drportal", verifier: "proof", totp_code: code });
  expect(new Headers(init!.headers).has("Authorization")).toBe(false);
});
it.each([204, 200, 503])("revokes a rejected freshly minted bearer with a tab-surviving request at status %s", async status => {
  vi.stubGlobal("fetch", vi.fn(async () => status === 204 ? new Response(null, { status }) : json({}, status)));
  await expect(auth.logoutBearer(base, "rejected-bearer")).resolves.toBeNull();
  const [url, init] = vi.mocked(fetch).mock.calls[0]!;
  expect(url).toBe(base + "/api/v1/auth/logout");
  expect(init).toMatchObject({ method: "POST", headers: { "Content-Type": "application/json", Authorization: "Bearer rejected-bearer" }, keepalive: true, redirect: "error", credentials: "omit" });
});
it("treats unavailable bearer revocation as best effort without leaking its error", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("offline"); }));
  await expect(auth.logoutBearer(base, "rejected-bearer")).resolves.toBeNull();
});
it.each(["login", "logout"])("preserves status, machine code and safe error copy for %s", async flow => {
  vi.stubGlobal("fetch", vi.fn(async () => json({ detail: "session policy rejected", code: "policy_required" }, 403)));
  const request = flow === "login" ? auth.login(base, "drportal", "proof") : api.logout();
  await expect(request).rejects.toMatchObject({ status: 403, code: "policy_required", message: "session policy rejected" });
});
it.each([NaN, -1, 1.5, 1001, Number.MAX_SAFE_INTEGER + 1])("refuses an invalid caseload page offset %s before transport", async offset => {
  vi.stubGlobal("fetch", vi.fn(async () => json([])));
  await expect(api.patientsPage({ offset })).rejects.toMatchObject({ status: 0, message: "invalid patient page offset" });
  expect(fetch).not.toHaveBeenCalled();
});
it("allows the last bounded caseload page without silently skipping it", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => json([], 200, { "X-Patients-Revision": "1" })));
  await expect(api.patientsPage({ offset: 1000 })).resolves.toEqual({ patients: [], nextOffset: null, revision: "1" });
  expect(vi.mocked(fetch).mock.calls[0]![0]).toBe(base + "/api/v1/therapist/patients?limit=200&offset=1000");
});
it.each([null, {}, Array(201).fill({ user_id: "patient" })])("refuses malformed or oversized caseload response %j", async payload => {
  vi.stubGlobal("fetch", vi.fn(async () => json(payload)));
  await expect(api.patientsPage()).rejects.toMatchObject({ message: "server returned an invalid patients page" });
});
it.each([null, 7, "overview"])("refuses a non-object insight summary %s", async payload => {
  vi.stubGlobal("fetch", vi.fn(async () => json(payload)));
  await expect(api.patientInsights("patient")).rejects.toMatchObject({ message: "server returned an invalid insights summary" });
});
it.each([null, {}, Array(101).fill({ id: "note" })])("refuses malformed or oversized note response %j", async payload => {
  vi.stubGlobal("fetch", vi.fn(async () => json(payload)));
  await expect(api.notes("patient")).rejects.toMatchObject({ message: "server returned an invalid note page" });
});

it("restarts a changed caseload once and refuses a second changed snapshot", async () => {
  const { ApiError } = await import("../src/api");
  const page = vi.spyOn(api, "patientsPage").mockRejectedValue(new ApiError(409, "caseload changed", "collection_changed"));
  await expect(api.patients()).rejects.toMatchObject({ message: "caseload changed", status: 409, code: "collection_changed" });
  expect(page).toHaveBeenCalledTimes(2);
});
it.each([{ status: 401, code: "collection_changed" }, { status: 409, code: "other_conflict" }, { status: 503, code: undefined }])("does not retry a different caseload failure $status/$code", async ({ status, code }) => {
  const { ApiError } = await import("../src/api");
  const page = vi.spyOn(api, "patientsPage").mockRejectedValue(new ApiError(status, "service refused", code));
  await expect(api.patients()).rejects.toMatchObject({ message: "service refused", status, code });
  expect(page).toHaveBeenCalledTimes(1);
});
it.each(["upgrade", "downgrade", "change"])("refuses a caseload snapshot-mode %s while restarting from the first page", async kind => {
  const first = kind === "upgrade" ? undefined : "1";
  const second = kind === "downgrade" ? undefined : "2";
  const page = vi.spyOn(api, "patientsPage").mockImplementation(async ({ offset = 0 } = {}) => offset === 0
    ? { patients: [], nextOffset: 1, revision: first }
    : { patients: [], nextOffset: null, revision: second });
  await expect(api.patients()).rejects.toMatchObject({ status: 409, code: "collection_changed", message: "patients changed while paging; retry the request" });
  expect(page).toHaveBeenCalledTimes(4);
});
it("bounds an endless caseload continuation instead of leaving the portal loading forever", async () => {
  const page = vi.spyOn(api, "patientsPage").mockImplementation(async ({ offset = 0 } = {}) => ({ patients: [], nextOffset: offset + 1 }));
  await expect(api.patients()).rejects.toMatchObject({ message: "server keeps returning patient continuations — aborting the request" });
  expect(page).toHaveBeenCalledTimes(6);
});
