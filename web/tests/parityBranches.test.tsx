/** Branch completion for the P7 views: the full grant flow, instrument
 *  switching, queue recovery, the LLM-unavailable branch, blocked-export
 *  fallback, access-log pagination, and the rotation failure paths. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MeasuresView } from "../src/views/Measures";
import { ShareView } from "../src/views/Share";
import { SettingsView } from "../src/views/Settings";
import { decrypt, fromBase64 } from "../src/crypto/core";
import { buildAad } from "../src/crypto/aad";
import { setKvBackendForTests, type KvBackend } from "../src/kvstore";
import { enqueue, rejectedEntries } from "../src/offlineQueue";
import { vault } from "../src/vault";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { press, render, settle, textOf, typeInto } from "./helpers/rtr";

const ORIGIN = "http://localhost:5173";
const USER = "user-1";

const memoryBackend = (): KvBackend => {
  const map = new Map<string, string>();
  return {
    async getItem(k) {
      return map.get(k) ?? null;
    },
    async setItem(k, v) {
      map.set(k, v);
    },
    async removeItem(k) {
      map.delete(k);
    },
  };
};

async function pressNth(root: Awaited<ReturnType<typeof render>>, label: string, occurrence: number): Promise<void> {
  const { act } = await import("react");
  const matches = root.root.findAllByType("button").filter((node) => node.children.join("") === label);
  const target = matches[occurrence];
  if (!target) throw new Error(`no button #${occurrence} labeled ${JSON.stringify(label)}`);
  await act(async () => {
    target.props.onClick();
  });
}

beforeEach(() => {
  resetTestState();
  setKvBackendForTests(memoryBackend());
  installSession(USER);
  const key = () => new Uint8Array(new ArrayBuffer(32)).fill(8);
  vault.unlock({ authKey: key(), dataKey: key() }, USER);
});
afterEach(() => {
  vi.unstubAllGlobals();
  setKvBackendForTests(null);
});

describe("ShareView grant flow (the full path)", () => {
  it("accepts the disclosure, wraps the data key, and grants with the verifier", async () => {
    // A REAL therapist keypair so the wrap is real crypto, and the portal
    // side could open it.
    const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
    let binary = "";
    for (const b of spki) binary += String.fromCharCode(b);
    const spkiB64Real = btoa(binary);

    let grantBody: Record<string, unknown> | null = null;
    let grantHeaders: Record<string, string> = {};
    stubFetch((url, init) => {
      if (url.endsWith("/consents/pairing/lookup")) {
        return jsonResponse({ therapist_id: "t-9", display_name: "Dr. Cove", wrap_pub_key: spkiB64Real });
      }
      if (url.endsWith("/consents") && init.method === "POST") {
        grantBody = JSON.parse(String(init.body)) as Record<string, unknown>;
        grantHeaders = init.headers as Record<string, string>;
        return jsonResponse({ id: "b".repeat(32), therapist_id: "t-9", display_name: "Dr. Cove", username: "cove", status: "active", granted_at: "2026-09-25T00:00:00Z", revoked_at: null });
      }
      if (url.endsWith("/consents")) {
        return jsonResponse([{ id: "b".repeat(32), therapist_id: "t-9", display_name: "Dr. Cove", username: "cove", status: "active", granted_at: "2026-09-25T00:00:00Z", revoked_at: null }]);
      }
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<ShareView />);
    await settle(40, 3);
    await typeInto(root, "Pairing code", "ZZ99ZZ99");
    await press(root, "Look up");
    await settle(40, 3);
    // Accept BOTH gates (W-4): the fingerprint-match attestation first,
    // then the disclosure terms — grant stays disabled otherwise.
    const checkboxes = root.root.findAllByType("input").filter((node) => node.props.type === "checkbox");
    expect(checkboxes).toHaveLength(2);
    const { act } = await import("react");
    for (const checkbox of checkboxes) {
      await act(async () => {
        checkbox.props.onChange({ target: { checked: true } });
      });
    }
    await press(root, "Confirm and share");
    await settle(60, 4);
    expect(grantBody).not.toBeNull();
    expect(grantBody!.code).toBe("ZZ99ZZ99");
    expect(grantBody!.disclosure).toBe("v2");
    expect(typeof grantBody!.ephemeral_pub).toBe("string");
    expect(typeof grantBody!.wrapped_key).toBe("string");
    expect(grantHeaders["X-Account-Verifier"]).toBeTruthy();
    expect(textOf(root)).toContain("Shared with Dr. Cove");
  });
});

describe("MeasuresView branches", () => {
  it("switches instruments and records a GAD-7 without the item-9 pointer", async () => {
    let created: { blob: string; client_measure_id: string } | null = null;
    stubFetch((url, init) => {
      if (url.endsWith("/measures") && init.method === "POST") {
        created = JSON.parse(String(init.body)) as { blob: string; client_measure_id: string };
        return jsonResponse({ id: "row" }, { status: 201 });
      }
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) {
        return jsonResponse(
          created ? [{ id: "row", client_measure_id: created.client_measure_id, blob: created.blob, measure_date: "2026-09-25", received_at: "r" }] : [],
          { headers: { "X-Measures-Revision": "3" } },
        );
      }
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(40, 3);
    await press(root, "GAD-7");
    await settle(40, 2);
    for (let index = 0; index < 7; index += 1) {
      await pressNth(root, "Several days", index);
    }
    await press(root, "Save measure");
    await settle(40, 4);
    expect(created).not.toBeNull();
    expect(textOf(root)).toContain("GAD-7 — 1 record");
    expect(textOf(root)).not.toContain("thoughts of harming yourself");
    // The decrypted payload names the instrument:
    const opened = await decrypt(vault.get().dataKey, fromBase64(created!.blob), buildAad("measure", USER, created!.client_measure_id));
    expect(JSON.parse(new TextDecoder().decode(opened)).measure).toBe("gad7");
  });

  it("a 409 (same-day replay) reads as already recorded", async () => {
    stubFetch((url, init) => {
      if (url.endsWith("/measures") && init.method === "POST") {
        return jsonResponse({ detail: "exists", code: "conflict" }, { status: 409 });
      }
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) return jsonResponse([], { headers: { "X-Measures-Revision": "1" } });
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(40, 3);
    for (let index = 0; index < 9; index += 1) {
      await pressNth(root, "Not at all", index);
    }
    await press(root, "Save measure");
    await settle(40, 3);
    expect(textOf(root)).toContain("Already recorded today");
  });
});

describe("SettingsView branches", () => {
  function coreStubs(extra?: { llm?: () => Response; export?: () => Response; access?: (cursor?: string) => Response; rekey?: () => Response }) {
    return stubFetch((url, init) => {
      if (url.endsWith("/meta")) return jsonResponse({ version: "1", api_version: "v1", unlock_days: 30, llm_available: true, sharing_available: true, sharing_disclosure_version: "v2" });
      if (url.endsWith("/llm-consent") && init.method === "GET") return (extra?.llm ?? (() => jsonResponse({ enabled: false })))();
      if (url.endsWith("/llm-consent") && init.method === "PUT") {
        return jsonResponse({ detail: "no provider configured", code: "llm_unavailable" }, { status: 409 });
      }
      if (url.endsWith("/account/export")) return (extra?.export ?? (() => new Response("{}", { status: 200 })))();
      if (url.endsWith("/access-log")) {
        const cursor = new URL(url, ORIGIN).searchParams.get("cursor") ?? undefined;
        return (extra?.access ?? ((c) => jsonResponse(c ? [] : [{ at: "2026-09-25T10:00:00Z", action: "entry.create", actor: "self" }], c ? {} : { headers: { "X-Next-Cursor": "cur-1" } })))(cursor);
      }
      if (url.endsWith("/processing/rekey")) return (extra?.rekey ?? (() => new Response(null, { status: 204 })))();
      if (url.endsWith("/processing/sessions")) return jsonResponse({ session_token: "pst", expires_in: 300 });
      if (url.endsWith("/consents")) return jsonResponse([]);
      return jsonResponse({}, { status: 404 });
    });
  }

  it("llm_unavailable surfaces the honest branch", async () => {
    coreStubs();
    const root = await render(<SettingsView onLockdown={() => undefined} />);
    await settle(40, 3);
    await press(root, "Enable LLM analysis");
    await settle(40, 3);
    expect(textOf(root)).toContain("does not offer LLM analysis");
  });

  it("the access log pages via Show more", async () => {
    coreStubs();
    const root = await render(<SettingsView onLockdown={() => undefined} />);
    await settle(40, 3);
    expect(textOf(root)).toContain("entry.create");
    await press(root, "Show more");
    await settle(40, 3);
    expect(root.root.findAllByType("button").some((node) => node.children.join("") === "Show more")).toBe(false);
  });

  it("queue recovery re-queues rejected entries", async () => {
    coreStubs();
    // Park a rejected entry through the REAL path: enqueue, then a flush
    // against a lying 409 (verify-GET 404) — mobile audit M-5 semantics.
    const { enqueue, flushQueue } = await import("../src/offlineQueue");
    await enqueue({ userId: USER, clientEntryId: "e-2026-09-25-r1", blobB64: "QUJD", entryDate: "2026-09-25" });
    stubFetch((url) => {
      if (url.endsWith("/entries")) return jsonResponse({ detail: "exists", code: "conflict" }, { status: 409 });
      if (url.includes("/entries/e-2026-09-25-r1")) return jsonResponse({ detail: "no", code: "not_found" }, { status: 404 });
      return jsonResponse({}, { status: 404 });
    });
    await flushQueue(USER);
    expect(await rejectedEntries(USER)).toHaveLength(1);
    const root = await render(<SettingsView onLockdown={() => undefined} />);
    await settle(40, 3);
    expect(textOf(root)).toContain("held back after server refusals");
    await press(root, "Re-queue recovered entries");
    await settle(40, 3);
    expect(textOf(root)).toContain("re-queued");
    expect(await rejectedEntries(USER)).toHaveLength(0);
  });

  it("a rekey key mismatch with an UNREADABLE corpus LOCKS DOWN with the honest already-rotated message (H-4 + B-3, audit 2026-09-26)", async () => {
    // The old copy claimed "NOTHING was changed" — false when a previous
    // attempt already rekeyed the corpus. The mismatch ladder verifies the
    // candidate key against a live entry first; the entries endpoint here
    // 404s, so verification fails. B-3 (follow-up): the corpus is provably
    // under a key this vault cannot read, so per the H-4 rule the session
    // must LOCK DOWN with the honest message — never a banner over live
    // keys that could keep writing under the dead old data key.
    coreStubs({ rekey: () => jsonResponse({ detail: "old key mismatch", code: "rekey_key_mismatch" }, { status: 400 }) });
    const onLockdown = vi.fn();
    const root = await render(<SettingsView onLockdown={onLockdown} />);
    await settle(40, 3);
    await typeInto(root, "New password", "another-new-password-9");
    await typeInto(root, "Confirm new password", "another-new-password-9");
    await press(root, "Change password");
    await settle(60, 4);
    expect(onLockdown).toHaveBeenCalledTimes(1);
    expect(onLockdown.mock.calls[0]![0]).toContain("already re-encrypted under a different new password");
    expect(onLockdown.mock.calls[0]![0]).not.toContain("NOTHING was changed");
  });
});

describe("SettingsView rotation with an active grant (the rewrap loop)", () => {
  it("rewraps the grant to the therapist's CURRENT public key before the credential dies", async () => {
    const order: string[] = [];
    const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
    let binary = "";
    for (const b of spki) binary += String.fromCharCode(b);
    const spkiB64 = btoa(binary);
    stubFetch((url, init) => {
      if (url.endsWith("/meta")) return jsonResponse({ version: "1", api_version: "v1", unlock_days: 30, llm_available: false, sharing_available: true, sharing_disclosure_version: "v2" });
      if (url.endsWith("/llm-consent")) return jsonResponse({ enabled: false });
      if (url.endsWith("/access-log")) return jsonResponse([]);
      if (url.endsWith("/processing/sessions")) {
        order.push("session");
        return jsonResponse({ session_token: `pst-${order.length}`, expires_in: 300 });
      }
      if (url.endsWith("/processing/rekey")) {
        order.push("rekey");
        return new Response(null, { status: 204 });
      }
      if (url.endsWith("/consents") && init.method === "GET") {
        return jsonResponse([{ id: "c".repeat(32), therapist_id: "t-4", display_name: "Dr. Ridge", username: "ridge", status: "active", granted_at: "2026-09-01T00:00:00Z", revoked_at: null, therapist_wrap_pub_key: spkiB64 }]);
      }
      if (url.endsWith("/rewrap")) {
        order.push("rewrap");
        return new Response(null, { status: 204 });
      }
      if (url.endsWith("/account/credential")) {
        order.push("credential");
        return new Response(null, { status: 204 });
      }
      return jsonResponse({}, { status: 404 });
    });
    const onLockdown = vi.fn();
    const root = await render(<SettingsView onLockdown={onLockdown} />);
    await settle(40, 3);
    await typeInto(root, "New password", "rotation-with-rewrap-9");
    await typeInto(root, "Confirm new password", "rotation-with-rewrap-9");
    await press(root, "Change password");
    await settle(60, 5);
    expect(order).toEqual(["session", "session", "rekey", "rewrap", "credential"]);
    expect(onLockdown).toHaveBeenCalledTimes(1);
  });

  it("an export failure surfaces honestly", async () => {
    stubFetch((url) => {
      if (url.endsWith("/meta")) return jsonResponse({ version: "1", api_version: "v1", unlock_days: 30, llm_available: false, sharing_available: true, sharing_disclosure_version: "v2" });
      if (url.endsWith("/llm-consent")) return jsonResponse({ enabled: false });
      if (url.endsWith("/access-log")) return jsonResponse([]);
      if (url.endsWith("/account/export")) return jsonResponse({ detail: "slow down", code: "rate_limited" }, { status: 429, headers: { "Retry-After": "5" } });
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<SettingsView onLockdown={() => undefined} />);
    await settle(40, 3);
    await press(root, "Download export (encrypted)");
    await settle(40, 3);
    expect(textOf(root)).toContain("export failed (429)");
  });
});

describe("MeasuresView multi-record trend", () => {
  it("renders one bar per decrypted record across instruments", async () => {
    const { encrypt, toBase64 } = await import("../src/crypto/core");
    const rows = [
      { id: "r1", client_measure_id: "m1", measure: "phq9", score: 12, date: "2026-09-18" },
      { id: "r2", client_measure_id: "m2", measure: "phq9", score: 7, date: "2026-09-25" },
    ];
    const encoded = await Promise.all(rows.map(async (row) => ({
      ...row,
      blob: toBase64(await encrypt(vault.get().dataKey, new TextEncoder().encode(JSON.stringify({ v: 1, measure: row.measure, score: row.score, completed_at: `${row.date}T10:00:00Z` })), buildAad("measure", USER, row.client_measure_id))),
    })));
    stubFetch((url) => {
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) {
        return jsonResponse(encoded.map(({ id, client_measure_id, blob, date }) => ({ id, client_measure_id, blob, measure_date: date, received_at: "r" })), { headers: { "X-Measures-Revision": "9" } });
      }
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(40, 4);
    expect(textOf(root)).toContain("PHQ-9 — 2 records");
  });
});
