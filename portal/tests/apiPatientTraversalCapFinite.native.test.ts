/** Separate tools-only API659 witness. Real ephemeral Node HTTP, native fetch
 * and native Response parsing consume client-accepted hostile/alternate legacy
 * wire. This is not current FastAPI short paging or a1200-account fixture. */
import { createServer, type Server } from "node:http";


import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, ApiError, clearSession, setSession } from "../src/api";

const TOKEN = "synthetic-finite-native-caseload-owner";
const nativeFetch = globalThis.fetch;
const PATIENT = {
  user_id: "0123456789abcdef0123456789abcdef",
  username: "Synthetic retained relationship", status: "revoked",
  granted_at: "2026-01-01T00:00:00Z", revoked_at: "2026-01-02T00:00:00Z",
  ephemeral_pub: null, wrapped_key: null,
};
type Witness = { requests: { offset: number; query: Record<string, string> }[]; transportFaults: string[] };
type Transport = { server: Server; origin: string; originals: Promise<Response>[]; restore: () => void };
let owned: Transport | undefined;

function witnessFor(): Witness {
  return { requests: [], transportFaults: [] };
}



function admitCompletedProducer(error: unknown, witness: Witness): void {
  if (witness.transportFaults.length) throw new Error(witness.transportFaults.join("; "));
  // Unexpected native body/connection/session/deadline faults are fixture or
  // execution failures, never finite semantic kill evidence. Completed typed
  // application refusals (including the prepared later503) remain observable.
  if (error !== undefined && (!(error instanceof ApiError)
    || /server unreachable|request timed out|response timed out|session ended/i.test(error.message))) {
    throw new Error(`SetupError: native public producer did not complete a typed application outcome: ${String(error)}`);
  }
}

async function openTransport(witness: Witness, continuationPages: number): Promise<Transport> {
  let origin = "";
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "", origin);
    const query = Object.fromEntries(url.searchParams), offset = Number(query.offset);
    if (request.method !== "GET" || url.pathname !== "/api/v1/therapist/patients"
      || query.limit !== "200" || !Number.isSafeInteger(offset) || offset < 0 || offset > continuationPages
      || Object.keys(query).sort().join(",") !== "limit,offset"
      || request.headers.authorization !== `Bearer ${TOKEN}`) {
      witness.transportFaults.push("SetupError: owned native HTTP receiver admission differs from the expected public API request");
      response.writeHead(500, { "Content-Type": "application/json" }); response.end(JSON.stringify({ detail: "owned native HTTP admission fault", code: "witness_setup_fault" }));
      return;
    }
    witness.requests.push({ offset, query });
    const status = offset >= continuationPages && continuationPages === 6 ? 503 : 200;
    const value = offset < continuationPages ? [PATIENT] : continuationPages === 6
      ? { detail: "synthetic later service refusal", code: "service_unavailable" }
      : [{ ...PATIENT, user_id: "fedcba9876543210fedcba9876543210", username: "Synthetic final relationship" }];
    response.once("finish", () => {  });
    response.writeHead(status, { "Content-Type": "application/json", ...(offset < continuationPages ? { "X-Next-Offset": String(offset + 1) } : {}) });
    response.end(JSON.stringify(value));
  });
  server.on("error", error => { witness.transportFaults.push(`SetupError: owned native HTTP server fault: ${String(error)}`); });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", () => { server.removeListener("error", reject); resolve(); }); });
  const address = server.address();
  if (!address || typeof address === "string") { server.closeAllConnections(); server.close(); throw new Error("SetupError: owned ephemeral loopback address is unavailable"); }
  origin = `http://127.0.0.1:${address.port}`;
  const originals: Promise<Response>[] = [];
  vi.stubGlobal("fetch", (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const target = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    if (target.origin !== origin || !init?.signal || init.signal.aborted || init.credentials !== "omit" || init.redirect !== "error" || init.cache !== "no-store") {
      throw new Error("SetupError: native fetch observation received an unowned origin or unexpected request policy");
    }
    // The only input normalization is URL conversion. This genuine native
    // Promise and its native HTTP Response are returned unchanged.
    const original = nativeFetch(target, init);

    void original.then(() => {  }, error => {
      witness.transportFaults.push(`SetupError: genuine native fetch did not complete: ${String(error)}`);
    });
    originals.push(original);
    return original;
  });
  const result = { server, origin, originals, restore: () => { vi.unstubAllGlobals();  } };
  owned = result;
  setSession(TOKEN, origin);
  return result;
}

async function retire(transport: Transport): Promise<void> {
  clearSession(); transport.restore();
  await Promise.allSettled(transport.originals);
  transport.server.closeAllConnections();
  await new Promise<void>((resolve, reject) => { transport.server.close(error => error ? reject(new Error(`SetupError: owned native HTTP retirement failed: ${String(error)}`)) : resolve()); });
   if (owned === transport) owned = undefined;
}

beforeEach(() => { vi.useRealTimers(); clearSession(); });
afterEach(async () => {
  // Independent fallback cleanup if opening/admission fails before the body's
  // owned finally path. No open server is carried into the next observation.
  clearSession(); vi.unstubAllGlobals(); vi.restoreAllMocks();
  const current = owned; owned = undefined;
  if (current) { await Promise.allSettled(current.originals); current.server.closeAllConnections(); await new Promise<void>(resolve => current.server.close(() => resolve())); }
});

it("refuses six native HTTP patient continuations before a later finite service error", async () => {
  const witness = witnessFor(); let transport: Transport | undefined;
  try {
    transport = await openTransport(witness, 6);
    const publicPromise = api.patients();
    const outcome = await publicPromise.then(value => ({ value, error: undefined as unknown }), error => ({ value: undefined, error: error as unknown }));
    await Promise.allSettled(transport.originals);
    admitCompletedProducer(outcome.error, witness);

    expect(outcome.value).toBeUndefined();
    expect(outcome.error).toMatchObject({ name: "ApiError", status: 0, message: "server keeps returning patient continuations — aborting the request" });
    expect(witness.requests.map(row => row.query)).toEqual(Array.from({ length: 6 }, (_, offset) => ({ limit: "200", offset: String(offset) })));

  }
  finally { if (transport) await retire(transport);  }
});

it("completes a finite native HTTP legacy traversal and deduplicates repeated relationship IDs", async () => {
  const witness = witnessFor(); let transport: Transport | undefined;
  try {
    transport = await openTransport(witness, 2);
    const publicPromise = api.patients();
    const outcome = await publicPromise.then(value => ({ value, error: undefined as unknown }), error => ({ value: undefined, error: error as unknown }));
    await Promise.allSettled(transport.originals);
    admitCompletedProducer(outcome.error, witness);

    expect(outcome.error).toBeUndefined();
    expect(outcome.value?.map(row => row.user_id)).toEqual([PATIENT.user_id, "fedcba9876543210fedcba9876543210"]);
    expect(witness.requests.map(row => row.query)).toEqual(Array.from({ length: 3 }, (_, offset) => ({ limit: "200", offset: String(offset) })));

  }
  finally { if (transport) await retire(transport);  }
});
