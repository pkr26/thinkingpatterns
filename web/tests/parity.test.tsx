/** P7 view suites: measures (encrypted records, trend, item-9 pointer),
 *  sharing (lookup → fingerprint → disclosure → fresh-step-up grant →
 *  revoke), settings (LLM consent, access log, export download, queue
 *  recovery, rotation flow, delete gates). Real crypto; fetch stubs. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MeasuresView } from "../src/views/Measures";
import { ShareView } from "../src/views/Share";
import { SettingsView } from "../src/views/Settings";
import { setKvBackendForTests, type KvBackend } from "../src/kvstore";
import { vault } from "../src/vault";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { isDisabled, press, pressSwitch, render, settle, textOf, textOfNode, typeInto } from "./helpers/rtr";

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
    async compareAndSet(k,before,after){
      if((map.get(k)??null)!==before)return false;
      map.set(k,after);return true;
    },
  };
};

/** Press the n-th button carrying the same label (questionnaire items
 *  repeat option labels — press() alone would only ever hit item 1). */
async function pressNth(root: Awaited<ReturnType<typeof render>>, label: string, occurrence: number): Promise<void> {
  const { act } = await import("react");
  const { textOfNode } = await import("./helpers/rtr");
  const matches = root.root.findAllByType("button").filter((node) => textOfNode(node) === label);
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

describe("MeasuresView", () => {
  it("records an encrypted PHQ-9 and renders the trend from decrypted rows", async () => {
    let created: { blob: string; client_measure_id: string } | null = null;
    stubFetch((url, init) => {
      if (url.endsWith("/measures") && init.method === "POST") {
        created = JSON.parse(String(init.body)) as { blob: string; client_measure_id: string };
        return jsonResponse({ id: "row" }, { status: 201 });
      }
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) {
        // The list returns the SERVER row (the just-created blob echoes back,
        // under the SAME client_measure_id the AAD was bound to).
        return jsonResponse(
          created
            ? [{ id: "row", client_measure_id: created.client_measure_id, blob: created.blob, measure_date: "2026-09-25", received_at: "r" }]
            : [],
          { headers: { "X-Measures-Revision": "1" } },
        );
      }
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(40, 3);
    // Answer all 9 PHQ-9 items (index 8 = item 9, endorse it).
    for (let index = 0; index < 9; index += 1) {
      await pressNth(root, index === 8 ? "More than half the days" : "Not at all", index);
    }
    await press(root, "Save measure");
    await settle(40, 4);
    expect(created).not.toBeNull();
    // The wire blob is opaque ciphertext:
    expect(created!.blob).not.toContain("phq9");
    // The item-9 pointer appears AFTER the save:
    expect(textOf(root)).toContain("thoughts of self-harm");
    expect(textOf(root)).toContain("does not monitor this response");
    // The trend renders from the decrypted row:
    expect(textOf(root)).toContain("PHQ-9 — 1 record");
  });

  it("refuses to save an incomplete measure", async () => {
    const mock = stubFetch(() => jsonResponse({}, { status: 404 }));
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(40, 3);
    await press(root, "Save measure");
    await settle(40, 2);
    expect(textOf(root)).toContain("Answer every question first");
    const posted = mock.mock.calls.filter(([url, init]) => String(url).endsWith("/measures") && init?.method === "POST");
    expect(posted).toHaveLength(0);
  });
});

describe("ShareView", () => {
  it("lookup shows the therapist + fingerprint; grant requires BOTH attestations (W-4)", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    stubFetch((url, init) => {
      calls.push({ url, init });
      if (url.endsWith("/consents/pairing/lookup")) {
        return jsonResponse({ therapist_id: "t-1", display_name: "Dr. River", wrap_pub_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcokO" + "B".repeat(60) });
      }
      if (new URL(url).pathname.endsWith("/consents") && init.method === "GET") return jsonResponse([]);
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<ShareView />);
    await settle(40, 3);
    await typeInto(root, "Pairing code", "AB12CD34");
    await press(root, "Look up");
    await settle(40, 3);
    expect(textOf(root)).toContain("Dr. River");
    expect(textOf(root)).toContain("fingerprint");
    const confirm = root.root.findAllByType("button").find((node) => textOfNode(node) === "Confirm and share");
    const checkboxes = root.root.findAllByType("input").filter((node) => node.props.type === "checkbox");
    // Two gates now: fingerprint-match attestation + disclosure terms.
    expect(checkboxes).toHaveLength(2);
    const { act } = await import("react");
    const toggle = async (index: number, checked: boolean): Promise<void> => {
      const checkbox = checkboxes[index]!;
      await act(async () => {
        checkbox.props.onChange({ target: { checked } });
      });
    };
    // Disabled with NEITHER attestation:
    expect(confirm?.props.disabled).toBe(true);
    // Disabled with ONLY the fingerprint attestation (mobile C-7 parity
    // means neither gate is optional):
    await toggle(0, true);
    expect(confirm?.props.disabled).toBe(true);
    // Disabled with ONLY the disclosure:
    await toggle(0, false);
    await toggle(1, true);
    expect(confirm?.props.disabled).toBe(true);
    // Enabled only with BOTH:
    await toggle(0, true);
    expect(confirm?.props.disabled).toBe(false);
    // Nothing was granted anywhere along the way — no premature POST:
    expect(calls.some((call) => call.url.endsWith("/consents") && call.init.method === "POST")).toBe(false);
  });

  it("a failed lookup explains expired codes", async () => {
    stubFetch((url) => {
      if (url.endsWith("/consents/pairing/lookup")) return jsonResponse({ detail: "no such code" }, { status: 404 });
      if (new URL(url).pathname.endsWith("/consents")) return jsonResponse([]);
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<ShareView />);
    await settle(40, 3);
    await typeInto(root, "Pairing code", "XXXXXXXX");
    await press(root, "Look up");
    await settle(40, 3);
    expect(textOf(root)).toContain("codes expire after 15 minutes");
  });

  it("SAS display (2026-09-26): the lookup's sas + wrap-key fingerprint render with compare-out-of-band copy and the patient's own pairing id", async () => {
    stubFetch((url) => {
      if (url.endsWith("/consents/pairing/lookup")) {
        return jsonResponse({
          therapist_id: "t-1",
          display_name: "Dr. River",
          wrap_pub_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcokO" + "B".repeat(60),
          sas: "482 913",
          wrap_key_fingerprint: "a1b2c3d4e5f60718",
        });
      }
      if (new URL(url).pathname.endsWith("/consents")) return jsonResponse([]);
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<ShareView />);
    await settle(40, 3);
    await typeInto(root, "Pairing code", "AB12CD34");
    await press(root, "Look up");
    await settle(40, 3);
    // The SAS itself, the server-side key fingerprint, the patient's own
    // pairing id (the input the therapist's portal needs), and the honest
    // compare-by-voice instruction — including the STOP on mismatch.
    expect(textOf(root)).toContain("482 913");
    expect(textOf(root)).toContain("a1b2c3d4e5f60718");
    expect(textOf(root)).toContain(USER);
    expect(textOf(root)).toContain("Read this verification code to your therapist");
    expect(textOf(root)).toContain("shows exactly the same");
  });

  it("a backend predating the SAS fields hides the comparison block (the local fingerprint check stays)", async () => {
    stubFetch((url) => {
      if (url.endsWith("/consents/pairing/lookup")) {
        return jsonResponse({ therapist_id: "t-1", display_name: "Dr. Old", wrap_pub_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcokO" + "B".repeat(60) });
      }
      if (new URL(url).pathname.endsWith("/consents")) return jsonResponse([]);
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<ShareView />);
    await settle(40, 3);
    await typeInto(root, "Pairing code", "AB12CD34");
    await press(root, "Look up");
    await settle(40, 3);
    expect(textOf(root)).toContain("Dr. Old");
    expect(textOf(root)).not.toContain("Read this verification code");
    // The pre-wave out-of-band check still renders.
    expect(textOf(root)).toContain("fingerprint");
  });

  it("revoke is fresh-step-up-gated and says what it honestly does", async () => {
    const consent = {
      id: "a".repeat(32),
      therapist_id: "t-1",
      display_name: "Dr. River",
      username: "river",
      status: "active",
      granted_at: "2026-09-01T00:00:00Z",
      revoked_at: null,
    };
    let revoked = false;
    stubFetch((url, init) => {
      if (new URL(url).pathname.endsWith("/consents") && init.method === "GET") {
        return jsonResponse(revoked ? [{ ...consent, status: "revoked", revoked_at: "2026-09-25T00:00:00Z" }] : [consent]);
      }
      if (url.endsWith(`/consents/${consent.id}`) && init.method === "DELETE") {
        revoked = true;
        return new Response(null, { status: 204 });
      }
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<ShareView />);
    await settle(40, 3);
    expect(textOf(root)).toContain("Dr. River");
    await press(root, "Revoke access");
    await press(root, "Revoke access"); // two-step confirm (redesign 2026-09-26)
    const reauth = await import("../src/reauth");
    vi.spyOn(reauth, "freshStepUp").mockResolvedValueOnce({ ok: true, proof: "revoke-proof" });
    await typeInto(root, "Current password", "freshly typed password");
    await press(root, "Verify and continue");
    await settle(40, 3);
    expect(textOf(root)).toContain("cannot be unread");
  });
});

describe("SettingsView", () => {
  it("toggles transcript-translation consent with fresh step-up and reports honestly", async () => {
    let enabled = false;
    stubFetch((url, init) => {
      if (url.endsWith("/meta")) return jsonResponse({ version: "1", api_version: "v1", unlock_days: 30, llm_available: true, sharing_available: true, sharing_disclosure_version: "v3" });
      if (url.endsWith("/llm-consent") && init.method === "GET") return jsonResponse({ enabled, active_for_current_policy: enabled });
      if (url.endsWith("/llm-consent") && init.method === "PUT") {
        enabled = (JSON.parse(String(init.body)) as { enabled: boolean }).enabled;
        return jsonResponse({ enabled, active_for_current_policy: enabled });
      }
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<SettingsView onLockdown={() => undefined} />);
    await settle(40, 3);
    expect(textOf(root)).toContain("off");
    // 2026-09-27: Settings renders TWO switches now — press the LLM one.
    await pressSwitch(root, "transcript translation");
    const reauth = await import("../src/reauth");
    vi.spyOn(reauth, "freshStepUp").mockResolvedValueOnce({ ok: true, proof: "llm-proof" });
    await typeInto(root, "Current password", "freshly typed password");
    await press(root, "Verify and continue");
    await settle(40, 3);
    expect(textOf(root)).toContain("enabled for your account");
  });

  it("export downloads the encrypted bundle via the seam", async () => {
    stubFetch((url) => {
      if (url.endsWith("/account/export")) return new Response('{"bundle":"ciphertext"}', { status: 200 });
      if (url.endsWith("/meta")) return jsonResponse({ version: "1", api_version: "v1", unlock_days: 30, llm_available: false, sharing_available: true, sharing_disclosure_version: "v3" });
      if (url.endsWith("/llm-consent")) return jsonResponse({ enabled: false });
      if (url.endsWith("/access-log")) return jsonResponse([], {});
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<SettingsView onLockdown={() => undefined} />);
    await settle(40, 3);
    await press(root, "Download export (encrypted)");
    await settle(40, 3);
    expect(textOf(root)).toContain("unreadable without your password");
  });

  it("deletion requires the typed confirmation", async () => {
    const mock = stubFetch((url) => {
      if (url.endsWith("/meta")) return jsonResponse({ version: "1", api_version: "v1", unlock_days: 30, llm_available: false, sharing_available: true, sharing_disclosure_version: "v3" });
      if (url.endsWith("/llm-consent")) return jsonResponse({ enabled: false });
      if (url.endsWith("/access-log")) return jsonResponse([], {});
      return jsonResponse({}, { status: 404 });
    });
    const onLockdown = vi.fn();
    const root = await render(<SettingsView onLockdown={onLockdown} />);
    await settle(40, 3);
    // F3 (2026-09-26): the gate moved into the button state — with
    // anything but the exact word typed, the destructive button is
    // disabled outright, so no click path exists to drive.
    await typeInto(root, "Type DELETE to confirm", "no");
    await settle(40, 3);
    expect(isDisabled(root, "Delete my account")).toBe(true);
    expect(mock.mock.calls.some(([url, init]) => String(url).endsWith("/account") && init?.method === "DELETE")).toBe(false);
    expect(onLockdown).not.toHaveBeenCalled();
    // The exact word arms it; nothing has been pressed yet.
    await typeInto(root, "Type DELETE to confirm", "DELETE");
    await settle(40, 3);
    expect(isDisabled(root, "Delete my account")).toBe(false);
    expect(mock.mock.calls.some(([url, init]) => String(url).endsWith("/account") && init?.method === "DELETE")).toBe(false);
    expect(onLockdown).not.toHaveBeenCalled();
  });

  it("rotation commits rekey + sharing wraps + credential atomically (epoch death disclosed)", async () => {
    const order: string[] = [];
    stubFetch((url, init) => {
      if (url.endsWith("/meta")) return jsonResponse({ version: "1", api_version: "v1", unlock_days: 30, llm_available: false, sharing_available: true, sharing_disclosure_version: "v3" });
      if (url.endsWith("/llm-consent")) return jsonResponse({ enabled: false });
      if (url.endsWith("/access-log")) return jsonResponse([]);
      if (url.endsWith("/processing/sessions")) {
        order.push("session");
        return jsonResponse({ session_token: `pst-${order.length}`, expires_in: 300 });
      }
      if (url.endsWith("/processing/rekey")) {
        order.push("rekey");
        const body=JSON.parse(String(init.body));
        expect(Array.isArray(body.consent_wraps)).toBe(true);
        return jsonResponse({credential_rotated:true,operation_id:body.operation_id});
      }
      if (new URL(url).pathname.endsWith("/consents") && init.method === "GET") return jsonResponse([]);
      if (url.endsWith("/account/credential")) {
        order.push("credential");
        return new Response(null, { status: 204 });
      }
      return jsonResponse({}, { status: 404 });
    });
    const onLockdown = vi.fn();
    const root = await render(<SettingsView onLockdown={onLockdown} />);
    await settle(40, 3);
    await typeInto(root, "New password", "a-brand-new-passcode-1");
    await typeInto(root, "Confirm new password", "a-brand-new-passcode-1");
    await press(root, "Change password");
    await settle(60, 5);
    expect(order).toEqual(["session", "session", "rekey"]);
    expect(onLockdown).toHaveBeenCalledTimes(1);
    expect(onLockdown.mock.calls[0]![0]).toContain("mobile app");
  });
});
