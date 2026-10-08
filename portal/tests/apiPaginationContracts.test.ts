import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, clearSession, setSession } from "../src/api";
const base = "https://clinic.example.com";
const json = (body: unknown, headers: HeadersInit = {}) => new Response(JSON.stringify(body), { headers });
beforeEach(() => { clearSession(); setSession("paging-bearer", base); });
afterEach(() => { clearSession(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
const resources = [
  { name: "patients", header: "X-Patients-Revision", size: 200, path: "/therapist/patients", rows: "patients", invoke: (params: {offset?: number; expectedRevision?: string}) => api.patientsPage(params) },
  { name: "evidence", header: "X-Entries-Revision", size: 25, path: "/therapist/patients/patient%20%2F1/entries", rows: "entries", invoke: (params: {offset?: number; expectedRevision?: string}) => api.patientEntries("patient /1", params) },
  { name: "measures", header: "X-Measures-Revision", size: 100, path: "/therapist/patients/patient%20%2F1/measures", rows: "measures", invoke: (params: {offset?: number; expectedRevision?: string}) => api.patientMeasures("patient /1", params) },
  { name: "note", header: "X-Notes-Revision", size: 100, path: "/therapist/patients/patient%20%2F1/notes", rows: "notes", invoke: (params: {offset?: number; expectedRevision?: string}) => api.notes("patient /1", params) },
];
it.each(resources)("retains the exact signed-64-bit $name snapshot while URL-encoding patient custody", async resource => {
  vi.stubGlobal("fetch", vi.fn(async () => json([{ id: "row-1" }], { [resource.header]: "9223372036854775807", "X-Next-Offset": "4" })));
  await expect(resource.invoke({ offset: 3, expectedRevision: "9223372036854775807" })).resolves.toMatchObject({ revision: "9223372036854775807", nextOffset: 4, [resource.rows]: [{ id: "row-1" }] });
  const url = new URL(String(vi.mocked(fetch).mock.calls[0]![0]));
  expect(url.pathname).toBe("/api/v1" + resource.path);
  expect(Object.fromEntries(url.searchParams)).toEqual({ limit: String(resource.size), offset: "3", expected_revision: "9223372036854775807", ...(resource.name === "patients" ? {} : { page_bytes: "2097152" }) });
});
it.each(resources)("uses canonical default $name page options without inventing filters", async resource => {
  vi.stubGlobal("fetch", vi.fn(async () => json([])));
  await expect(resource.invoke({})).resolves.toMatchObject({ nextOffset: null, [resource.rows]: [] });
  const url = new URL(String(vi.mocked(fetch).mock.calls[0]![0]));
  expect(Object.fromEntries(url.searchParams)).toEqual({ limit: String(resource.size), ...(resource.name === "patients" ? { offset: "0" } : { page_bytes: "2097152" }) });
});
it.each(resources)("keeps the legacy full-page $name continuation and terminates a snapshot page", async resource => {
  const rows = Array.from({ length: resource.size }, (_, i) => ({ id: `row-${i}` }));
  vi.stubGlobal("fetch", vi.fn(async () => json(rows)));
  await expect(resource.invoke({ offset: 0 })).resolves.toMatchObject({ nextOffset: resource.size, revision: undefined });
  vi.stubGlobal("fetch", vi.fn(async () => json(rows, { [resource.header]: "7" })));
  await expect(resource.invoke({ offset: 0 })).resolves.toMatchObject({ nextOffset: resource.name === "patients" ? null : resource.size, revision: "7" });
});
it.each(["x1", "1x", "01", "1e0", "0x1", "-1", "1.5", "9007199254740993"])("rejects non-canonical continuation %s", async value => {
  vi.stubGlobal("fetch", vi.fn(async () => json([{ id: "row-1" }], { "X-Next-Offset": value })));
  for (const resource of resources) await expect(resource.invoke({})).rejects.toMatchObject({ message: `server returned an invalid ${resource.name} continuation` });
});
it.each(resources)("refuses an empty $name page advertising further evidence", async resource => {
  vi.stubGlobal("fetch", vi.fn(async () => json([], { "X-Next-Offset": "0" })));
  await expect(resource.invoke({})).rejects.toMatchObject({ message: `server returned an invalid ${resource.name} continuation` });
});
it.each(["x1", "1x", "01", "-1", "9223372036854775808", "9999999999999999999", "10000000000000000000"])("rejects malformed collection revision %s", async revision => {
  vi.stubGlobal("fetch", vi.fn(async () => json([], Object.fromEntries(resources.map(resource => [resource.header, revision])))));
  for (const resource of resources) await expect(resource.invoke({})).rejects.toMatchObject({ message: `server returned an invalid ${resource.name} snapshot revision` });
});
it.each(resources)("refuses a dropped or changed pinned $name snapshot", async resource => {
  for (const revision of [undefined, "8"]) {
    vi.stubGlobal("fetch", vi.fn(async () => json([], revision === undefined ? {} : { [resource.header]: revision })));
    await expect(resource.invoke({ expectedRevision: "7" })).rejects.toMatchObject({ message: resource.name === "patients" ? "patients changed while paging; retry the request" : revision === undefined ? `server dropped the ${resource.name} snapshot revision` : `server returned a changed ${resource.name} snapshot revision` });
  }
});
it.each([-1, 0.5, NaN, Number.MAX_SAFE_INTEGER + 1])("refuses malformed collection offset %s before I/O", async offset => {
  vi.stubGlobal("fetch", vi.fn(async () => json([])));
  for (const resource of resources) await expect(resource.invoke({ offset })).rejects.toMatchObject({ message: resource.name === "patients" ? "invalid patient page offset" : resource.name === "measures" ? "invalid measure page offset" : resource.name === "evidence" ? "invalid evidence page offset" : "invalid note page offset" });
  expect(fetch).not.toHaveBeenCalled();
});
it.each(resources)("rejects an invalid requested $name snapshot before I/O", async resource => {
  vi.stubGlobal("fetch", vi.fn(async () => json([])));
  await expect(resource.invoke({ expectedRevision: "x7" })).rejects.toMatchObject({ message: `invalid ${resource.name} snapshot revision` });
  expect(fetch).not.toHaveBeenCalled();
});
it("round-trips bounded evidence dates as encoded query parameters", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => json([], { "X-Entries-Revision": "7" })));
  await expect(api.patientEntries("patient", { since: "2026-09-01 + ?", until: "2026-09-30 + ?", offset: 2, expectedRevision: "7" })).resolves.toMatchObject({ entries: [], revision: "7" });
  const url = new URL(String(vi.mocked(fetch).mock.calls[0]![0]));
  expect(Object.fromEntries(url.searchParams)).toEqual({ limit: "25", page_bytes: "2097152", since: "2026-09-01 + ?", until: "2026-09-30 + ?", offset: "2", expected_revision: "7" });
});
