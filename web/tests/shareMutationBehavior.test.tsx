import { createDecipheriv, createHash, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, pbkdf2Sync } from "node:crypto";
import { act, StrictMode } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ShareView } from "../src/views/Share";
import { api, auth, ApiError, clearSession, type ListedConsent, type PairingLookup } from "../src/api/client";
import * as reauth from "../src/reauth";
import * as sharing from "../src/crypto/sharing";
import { vault } from "../src/vault";
import { __setLocaleForTests, t } from "../src/strings";
import { installSession, resetTestState } from "./helpers/api";
import { isDisabled, press, pressSwitch, render, setCheckbox, textOf, typeInto } from "./helpers/rtr";
import { publicSurface } from "./helpers/publicSurface";

const owner = "sharing-behavior-owner";
const actualFreshStepUp = reauth.freshStepUp;
const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const spki = pair.publicKey.export({ type: "spki", format: "der" });
const fingerprint = createHash("sha256").update(spki).digest("hex").slice(0, 32).toUpperCase().match(/.{4}/g)!.join(" ");
const found: PairingLookup = { therapist_id: "therapist-current", display_name: "Dr. Current", wrap_pub_key: spki.toString("base64"), sas: "123 456", wrap_key_fingerprint: "server fingerprint" };
const consent = (id = "a".repeat(32), fields: Partial<ListedConsent> = {}): ListedConsent => ({ id, therapist_id: found.therapist_id, display_name: found.display_name, username: "doctor-username", status: "active", granted_at: "2026-10-01T05:06:07Z", revoked_at: null, therapist_wrap_pub_key: found.wrap_pub_key, ...fields });
type Root = Awaited<ReturnType<typeof render>>;
const surface = (root: Root) => publicSurface(root.toJSON()).replaceAll(fingerprint, "DERIVED_THERAPIST_FINGERPRINT");
const flush = async () => { for (let i = 0; i < 8; i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 2)); }); };
function deferred<T>() { let resolve!: (value: T) => void, reject!: (error: unknown) => void; const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
async function lookup(root: Root) { await typeInto(root, t("share.webPairingCode"), "  PAIR1234  "); await press(root, t("share.webLookUp")); await flush(); }
async function requestGrant(root: Root) { await lookup(root); await setCheckbox(root, t("share.webFingerprintConfirm"), true); await setCheckbox(root, t("share.webDisclosureConfirm"), true); await press(root, t("share.webConfirmShare")); }
async function confirm(root: Root) { await typeInto(root, t("settings.reauthPasswordField"), "fresh patient password"); await press(root, t("settings.reauthConfirm")); await flush(); }
beforeEach(() => {
  resetTestState(); __setLocaleForTests("en"); installSession(owner);
  vault.unlock({ authKey: new Uint8Array(new ArrayBuffer(32)).fill(47), dataKey: new Uint8Array(new ArrayBuffer(32)).fill(49) }, owner);
  vi.spyOn(api, "listConsents").mockResolvedValue([]); vi.spyOn(api, "pairingLookup").mockResolvedValue(found);
  vi.spyOn(reauth, "freshStepUp").mockResolvedValue({ ok: true, proof: "fresh-action-proof" });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); __setLocaleForTests("en"); });

it.each(["en", "es"] as const)("renders actual current and past grants, voice scope, fallback identity and dated disclosure in %s", async locale => {
  __setLocaleForTests(locale); vi.mocked(api.listConsents).mockResolvedValue([consent(), consent("b".repeat(32), { display_name: "", username: "fallback-doctor", share_voice: true }), consent("c".repeat(32), { display_name: "Dr. Previous", status: "revoked", revoked_at: "2026-10-02" })]);
  const root = await render(<ShareView />); await flush(); expect(surface(root)).toMatchSnapshot();
  expect(textOf(root)).toContain("fallback-doctor"); expect(textOf(root)).toContain("2026-10-01"); expect(textOf(root)).toContain("Dr. Previous");
});
it("shows a load error while retaining the honest loading state", async () => {
  vi.mocked(api.listConsents).mockRejectedValue(new Error("consent service temporarily unavailable")); const root = await render(<ShareView />); await flush();
  expect(textOf(root)).toContain("consent service temporarily unavailable"); expect(surface(root)).toMatchSnapshot();
});
it("refuses an empty pairing code and trims a nonempty lookup before displaying real key verification details", async () => {
  const root = await render(<ShareView />); await press(root, t("share.webLookUp")); expect(textOf(root)).toContain(t("share.webCodeRule")); expect(api.pairingLookup).not.toHaveBeenCalled();
  await lookup(root); expect(api.pairingLookup).toHaveBeenCalledWith("PAIR1234"); expect(textOf(root)).toContain(fingerprint); expect(textOf(root)).toContain("123 456"); expect(textOf(root)).toContain("server fingerprint"); expect(textOf(root)).toContain(owner);
  expect(surface(root)).toMatchSnapshot(); expect(isDisabled(root, t("share.webConfirmShare"))).toBe(true);
  await setCheckbox(root, t("share.webFingerprintConfirm"), true); expect(isDisabled(root, t("share.webConfirmShare"))).toBe(true);
  await setCheckbox(root, t("share.webDisclosureConfirm"), true); expect(isDisabled(root, t("share.webConfirmShare"))).toBe(false);
});
it.each([new ApiError(404, "expired code"), new Error("pairing service unavailable")])("shows the appropriate failed lookup without stale therapist details: %#", async failure => {
  vi.mocked(api.pairingLookup).mockRejectedValue(failure); const root = await render(<ShareView />); await lookup(root);
  expect(textOf(root)).toContain(failure instanceof ApiError ? t("share.webCodeExpired") : failure.message); expect(textOf(root)).not.toContain(found.display_name); expect(surface(root)).toMatchSnapshot();
});
it("hides malformed optional comparison data while keeping a usable local fingerprint", async () => {
  vi.mocked(api.pairingLookup).mockResolvedValue({ ...found, sas: 123, wrap_key_fingerprint: ["not a string"] } as unknown as PairingLookup);
  const root = await render(<ShareView />); await lookup(root); expect(textOf(root)).toContain(fingerprint); expect(textOf(root)).not.toContain("not a string"); expect(surface(root)).toMatchSnapshot();
});
it.each([false, true])("copies only the displayed real key fingerprint and retains it if clipboard permission fails: failure=%s", async failure => {
  const write = vi.fn(async () => { if (failure) throw new Error("clipboard denied"); }); vi.stubGlobal("navigator", { clipboard: { writeText: write } });
  const root = await render(<ShareView />); await lookup(root); await press(root, t("share.copyFingerprint")); await flush();
  expect(write).toHaveBeenCalledWith(fingerprint); expect(textOf(root)).toContain(fingerprint); expect(textOf(root)).toContain(t(failure ? "share.copyFingerprint" : "share.copiedFingerprint"));
});
it("keeps the fingerprint selectable and does not claim success when this browser has no clipboard API", async () => {
  vi.stubGlobal("navigator", {}); const root = await render(<ShareView />); await lookup(root); await press(root, t("share.copyFingerprint")); await flush();
  expect(textOf(root)).toContain(fingerprint); expect(textOf(root)).toContain(t("share.copyFingerprint")); expect(textOf(root)).not.toContain(t("share.copiedFingerprint"));
});
it("requires fresh action-bound authentication, wraps the actual live key, and clears its transferred temporary key after grant", async () => {
  const actual = sharing.wrapDataKeyForTherapist, owned: Uint8Array[] = [], caller = vault.get().dataKey, before = caller.slice();
  const grant = vi.spyOn(api, "grantConsent").mockImplementation(async (_code, ephemeral, wrapped) => {
    const ephemeralDer = Buffer.from(ephemeral, "base64"), shared = diffieHellman({ privateKey: pair.privateKey, publicKey: createPublicKey({ key: ephemeralDer, format: "der", type: "spki" }) });
    const kek = hkdfSync("sha256", shared, Buffer.concat([ephemeralDer, spki]), Buffer.from("mindpattern/wrap/v1"), 32), wire = Buffer.from(wrapped, "base64");
    const decrypt = createDecipheriv("aes-256-gcm", Buffer.from(kek), wire.subarray(0, 12)); decrypt.setAAD(Buffer.from(JSON.stringify(["consent-wrap", owner, found.therapist_id]))); decrypt.setAuthTag(wire.subarray(-16));
    expect(Buffer.concat([decrypt.update(wire.subarray(12, -16)), decrypt.final()])).toEqual(Buffer.from(before)); return consent();
  });
  vi.spyOn(sharing, "wrapDataKeyForTherapist").mockImplementation(async (...args) => { owned.push(args[0]); return actual(...args); });
  const root = await render(<ShareView />); await requestGrant(root); expect(surface(root)).toMatchSnapshot(); expect(isDisabled(root, t("settings.reauthConfirm"))).toBe(true);
  await confirm(root); expect(reauth.freshStepUp).toHaveBeenCalledWith("fresh patient password", "sharing_grant"); expect(grant).toHaveBeenCalledWith("PAIR1234", expect.any(String), expect.any(String), "fresh-action-proof");
  expect(owned.length).toBeGreaterThan(0); for (const key of owned) expect(key).toEqual(new Uint8Array(key.length)); expect(caller).toEqual(before);
  expect(textOf(root)).toContain(t("share.webGrantedStatus", { name: found.display_name })); expect(root.root.findAllByType("input").every(node => node.props.type !== "password" && node.props.type !== "checkbox")).toBe(true); expect(api.listConsents).toHaveBeenCalledTimes(2);
  expect(root.root.findAllByType("input").find(node => node.props.type === "text")!.props.value).toBe("");
});
it("works after React StrictMode performs its effect cleanup and remount", async () => {
  const root = await render(<StrictMode><ShareView /></StrictMode>); await lookup(root); expect(textOf(root)).toContain(found.display_name); expect(textOf(root)).toContain(fingerprint);
});
it.each(["code", "session", "keys"] as const)("does not send a password proof after a real key wrap completes for a retired operation: %s", async retired => {
  const gate = deferred<void>(), started = deferred<void>(), real = sharing.wrapDataKeyForTherapist;
  vi.spyOn(sharing, "wrapDataKeyForTherapist").mockImplementation(async (...args) => { const result = await real(...args); started.resolve(); await gate.promise; return result; });
  const grant = vi.spyOn(api, "grantConsent").mockResolvedValue(consent()); const root = await render(<ShareView />); await requestGrant(root); await confirm(root); await started.promise;
  if (retired === "code") await typeInto(root, t("share.webPairingCode"), "REPLACED"); else if (retired === "session") clearSession(); else vault.unlock({ authKey: new Uint8Array(new ArrayBuffer(32)).fill(51), dataKey: new Uint8Array(new ArrayBuffer(32)).fill(53) }, owner);
  await act(async () => { gate.resolve(); }); await flush(); expect(reauth.freshStepUp).not.toHaveBeenCalled(); expect(grant).not.toHaveBeenCalled();
});
it.each([false, true])("does not replace refreshed grants with a superseded initial load or late load error: failedOldLoad=%s", async failure => {
  const pending = deferred<ListedConsent[]>(); vi.mocked(api.listConsents).mockReturnValueOnce(pending.promise).mockResolvedValue([]); vi.spyOn(api, "grantConsent").mockResolvedValue(consent());
  const root = await render(<ShareView />); await requestGrant(root); await confirm(root); expect(api.listConsents).toHaveBeenCalledTimes(2);
  await act(async () => { if (failure) pending.reject(new Error("superseded initial load failed")); else pending.resolve([consent("d".repeat(32), { display_name: "Dr. Superseded" })]); }); await flush();
  expect(textOf(root)).not.toContain("Dr. Superseded"); expect(textOf(root)).not.toContain("superseded initial load failed");
});
it.each(["locked", "no-account", "wrong-password", "offline"] as const)("retains the action and clears its password after fresh authentication refuses it: %s", async reason => {
  vi.mocked(reauth.freshStepUp).mockResolvedValue({ ok: false, reason }); const grant = vi.spyOn(api, "grantConsent").mockResolvedValue(consent()); const root = await render(<ShareView />); await requestGrant(root); await confirm(root);
  const keys = { locked: "common.reauthLocked", "no-account": "common.reauthNoAccount", "wrong-password": "common.wrongPassword", offline: "common.reauthOffline" }; expect(textOf(root)).toContain(t(keys[reason])); expect(grant).not.toHaveBeenCalled(); expect(root.root.findAllByType("input").find(n => n.props.type === "password")!.props.value).toBe(""); expect(surface(root)).toMatchSnapshot();
});
it.each([new ApiError(409, "policy changed", "disclosure_outdated"), new Error("grant failed")])("keeps the pairing available after a failed grant and shows honest recovery: %#", async failure => {
  vi.spyOn(api, "grantConsent").mockRejectedValue(failure); const root = await render(<ShareView />); await requestGrant(root); await confirm(root);
  expect(textOf(root)).toContain(t(failure instanceof ApiError ? "share.webTermsChanged" : "share.webGrantFailed")); expect(textOf(root)).toContain(found.display_name); expect(surface(root)).toMatchSnapshot();
});
it("cancels a sensitive prompt without dispatching and clears its password", async () => {
  const grant = vi.spyOn(api, "grantConsent").mockResolvedValue(consent()); const root = await render(<ShareView />); await requestGrant(root); await typeInto(root, t("settings.reauthPasswordField"), "discard me"); await press(root, t("common.cancel"));
  expect(root.root.findAllByType("input").some(n => n.props.type === "password")).toBe(false); expect(grant).not.toHaveBeenCalled(); expect(reauth.freshStepUp).not.toHaveBeenCalled();
});
it("requires two revocation confirmations and sends the exact consent with its revoke proof before refreshing", async () => {
  vi.mocked(api.listConsents).mockResolvedValue([consent()]); const revoke = vi.spyOn(api, "revokeConsent").mockResolvedValue(null); const root = await render(<ShareView />); await flush();
  await press(root, t("share.webRevoke")); expect(reauth.freshStepUp).not.toHaveBeenCalled(); expect(surface(root)).toMatchSnapshot(); await press(root, t("common.cancel")); expect(revoke).not.toHaveBeenCalled();
  await press(root, t("share.webRevoke")); await press(root, t("share.webRevoke")); expect(surface(root)).toMatchSnapshot(); await confirm(root);
  expect(reauth.freshStepUp).toHaveBeenCalledWith("fresh patient password", "sharing_revoke"); expect(revoke).toHaveBeenCalledWith(consent().id, "fresh-action-proof"); expect(textOf(root)).toContain(t("share.webRevokedStatus", { name: found.display_name }));
});
it.each([false, true])("changes voice sharing only after its fresh proof and reloads honest state on failure: failure=%s", async failure => {
  vi.mocked(api.listConsents).mockResolvedValueOnce([consent()]).mockResolvedValue([consent(undefined, { share_voice: true })]); const voice = vi.spyOn(api, "setShareVoice"); if (failure) voice.mockRejectedValue(new Error("scope service failed")); else voice.mockResolvedValue({ id: consent().id, share_voice: true });
  const root = await render(<ShareView />); await flush(); await pressSwitch(root); expect(surface(root)).toMatchSnapshot(); expect(voice).not.toHaveBeenCalled(); await confirm(root);
  expect(reauth.freshStepUp).toHaveBeenCalledWith("fresh patient password", "sharing_voice"); expect(voice).toHaveBeenCalledWith(consent().id, true, "fresh-action-proof"); expect(api.listConsents).toHaveBeenCalledTimes(2); if (failure) expect(textOf(root)).toContain(t("share.voiceToggleFailed"));
  expect(textOf(root)).toContain(t("share.voiceOn"));
});
it.each(["code", "session", "unmount"] as const)("does not grant after a stale asynchronous proof completion: %s", async retired => {
  const pending = deferred<reauth.FreshStepUpResult>(); vi.mocked(reauth.freshStepUp).mockReturnValue(pending.promise); const grant = vi.spyOn(api, "grantConsent").mockResolvedValue(consent()); const root = await render(<ShareView />); await requestGrant(root); await confirm(root);
  expect(reauth.freshStepUp).toHaveBeenCalledTimes(1);
  if (retired === "code") await typeInto(root, t("share.webPairingCode"), "REPLACED"); else if (retired === "session") clearSession(); else await act(async () => { root.unmount(); });
  await act(async () => { pending.resolve({ ok: true, proof: "stale-proof" }); }); await flush(); expect(grant).not.toHaveBeenCalled();
});
it.each([new ApiError(503, "service unavailable"), new Error("revoke unavailable")])("retains the grant and shows a failed revocation without claiming success: %#", async failure => {
  vi.mocked(api.listConsents).mockResolvedValue([consent()]); vi.spyOn(api, "revokeConsent").mockRejectedValue(failure); const root = await render(<ShareView />); await flush(); await press(root, t("share.webRevoke")); await press(root, t("share.webRevoke")); await confirm(root);
  expect(textOf(root)).toContain(t("share.webRevokeFailed")); expect(textOf(root)).not.toContain(t("share.webRevokedStatus", { name: found.display_name })); expect(surface(root)).toMatchSnapshot();
});
it.each(["load", "lookup"] as const)("uses honest fallback copy for an empty public error: %s", async stage => {
  if (stage === "load") vi.mocked(api.listConsents).mockRejectedValue(new Error("")); else vi.mocked(api.pairingLookup).mockRejectedValue(new Error(""));
  const root = await render(<ShareView />); await flush(); if (stage === "lookup") await lookup(root); expect(textOf(root)).toContain(t(stage === "load" ? "share.webLoadFailed" : "share.webLookupFailed"));
});
it("displays the active progress and danger states while fresh revocation authentication is pending", async () => {
  const step = deferred<reauth.FreshStepUpResult>(); vi.mocked(reauth.freshStepUp).mockReturnValue(step.promise); vi.mocked(api.listConsents).mockResolvedValue([consent()]); const revoke = vi.spyOn(api, "revokeConsent").mockResolvedValue(null), root = await render(<ShareView />); await flush(); await press(root, t("share.webRevoke")); await press(root, t("share.webRevoke")); await confirm(root); expect(surface(root)).toMatchSnapshot(); expect(isDisabled(root, t("settings.working"))).toBe(true); expect(revoke).not.toHaveBeenCalled();
  await act(async () => { step.resolve({ ok: true, proof: "fresh-action-proof" }); }); await flush(); expect(revoke).toHaveBeenCalledTimes(1);
});
it("displays pairing progress and clears prior success before the next lookup completes", async () => {
  vi.spyOn(api, "grantConsent").mockResolvedValue(consent()); const root = await render(<ShareView />); await requestGrant(root); await confirm(root); const next = deferred<PairingLookup>(); vi.mocked(api.pairingLookup).mockReturnValue(next.promise); await typeInto(root, t("share.webPairingCode"), "NEXT-CODE"); await press(root, t("share.webLookUp")); expect(textOf(root)).not.toContain(t("share.webGrantedStatus", { name: found.display_name })); expect(surface(root)).toMatchSnapshot(); await act(async () => { next.resolve(found); }); await flush(); expect(textOf(root)).toContain(found.display_name);
});
it.each(["success", "error"] as const)("ignores a retired pairing response before key verification: %s", async outcome => {
  const pending = deferred<PairingLookup>(); vi.mocked(api.pairingLookup).mockReturnValue(pending.promise); const root = await render(<ShareView />); await lookup(root); await typeInto(root, t("share.webPairingCode"), "CHANGED-CODE"); await act(async () => { if (outcome === "error") pending.reject(new Error("retired pairing error")); else pending.resolve(found); }); await flush(); expect(textOf(root)).not.toContain(found.display_name); expect(textOf(root)).not.toContain("retired pairing error");
});
it.each(["en", "es"] as const)("names the fallback therapist identity in the voice authentication prompt: %s", async locale => {
  __setLocaleForTests(locale); vi.mocked(api.listConsents).mockResolvedValue([consent(undefined, { display_name: "", username: "fallback-clinician" })]); const root = await render(<ShareView />); await flush(); await pressSwitch(root); expect(textOf(root)).toContain(t("share.reauthShareVoiceTitle", { name: "fallback-clinician" })); expect(surface(root)).toMatchSnapshot();
});
it("retires an existing authentication prompt when its pairing code is replaced", async () => {
  const grant = vi.spyOn(api, "grantConsent").mockResolvedValue(consent()), root = await render(<ShareView />); await requestGrant(root); await typeInto(root, t("settings.reauthPasswordField"), "typed secret"); await typeInto(root, t("share.webPairingCode"), "REPLACEMENT"); expect(root.root.findAllByType("input").some(node => node.props.type === "password")).toBe(false); expect(grant).not.toHaveBeenCalled(); expect(reauth.freshStepUp).not.toHaveBeenCalled();
});
it("refuses a retired voice failure reload after account ownership changes", async () => {
  const reload = deferred<ListedConsent[]>(); vi.mocked(api.listConsents).mockResolvedValueOnce([consent()]).mockReturnValueOnce(reload.promise); vi.spyOn(api, "setShareVoice").mockRejectedValue(new Error("voice scope service failed")); const root = await render(<ShareView />); await flush(); await pressSwitch(root); await confirm(root); clearSession(); vault.lock(); await act(async () => { reload.resolve([consent(undefined, { display_name: "Dr. Retired Account", share_voice: true })]); }); await flush(); expect(textOf(root)).not.toContain("Dr. Retired Account");
});
it("rejects a superseded initial StrictMode load even when its effect is remounted", async () => {
  const first = deferred<ListedConsent[]>(), second = deferred<ListedConsent[]>(); vi.mocked(api.listConsents).mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise); const root = await render(<StrictMode><ShareView /></StrictMode>); expect(api.listConsents).toHaveBeenCalledTimes(2); await act(async () => { second.resolve([consent(undefined, { display_name: "Dr. Fresh Remount" })]); }); await flush(); await act(async () => { first.resolve([consent(undefined, { display_name: "Dr. Retired Mount" })]); }); await flush(); expect(textOf(root)).toContain("Dr. Fresh Remount"); expect(textOf(root)).not.toContain("Dr. Retired Mount");
});
it("shows honest non-expiry copy for a typed non-404 pairing failure", async () => {
  vi.mocked(api.pairingLookup).mockRejectedValue(new ApiError(503, "server-controlled detail")); const root = await render(<ShareView />); await lookup(root); expect(textOf(root)).toContain(t("errors.serverError")); expect(textOf(root)).not.toContain(t("share.webCodeExpired"));
});
it("hides a malformed comparison fingerprint independently of a usable server SAS", async () => {
  vi.mocked(api.pairingLookup).mockResolvedValue({ ...found, wrap_key_fingerprint: ["wrong fingerprint type"] } as unknown as PairingLookup); const root = await render(<ShareView />); await lookup(root); expect(textOf(root)).toContain(found.sas!); expect(textOf(root)).not.toContain("wrong fingerprint type"); expect(surface(root)).toMatchSnapshot();
});
it("clears prior verification details on same-code lookup retry and on code replacement", async () => {
  const root = await render(<ShareView />); await lookup(root); const next = deferred<PairingLookup>(); vi.mocked(api.pairingLookup).mockReturnValue(next.promise); await press(root, t("share.webLookUp")); expect(textOf(root)).not.toContain(found.display_name); await act(async () => { next.resolve(found); }); await flush(); expect(textOf(root)).toContain(found.display_name); await typeInto(root, t("share.webPairingCode"), "DIFFERENT-CODE"); expect(textOf(root)).not.toContain(found.display_name); expect(root.root.findAllByType("input").some(n => n.props.type === "checkbox")).toBe(false);
});
it("ignores a retired key-fingerprint completion after the real fingerprint was calculated", async () => {
  const gate = deferred<void>(), actual = sharing.keyFingerprint; vi.spyOn(sharing, "keyFingerprint").mockImplementation(async pub => { const value = await actual(pub); await gate.promise; return value; }); const root = await render(<ShareView />); await lookup(root); await typeInto(root, t("share.webPairingCode"), "REPLACED-CODE"); await act(async () => { gate.resolve(); }); await flush(); expect(textOf(root)).not.toContain(found.display_name); expect(textOf(root)).not.toContain(fingerprint);
});
it.each(["success", "error"] as const)("does not publish a grant response after the pairing operation retires: %s", async outcome => {
  const pending = deferred<ListedConsent>(); vi.spyOn(api, "grantConsent").mockReturnValue(pending.promise); const root = await render(<ShareView />); await requestGrant(root); await confirm(root); await typeInto(root, t("share.webPairingCode"), "REPLACEMENT-CODE"); await act(async () => { outcome === "success" ? pending.resolve(consent()) : pending.reject(new Error("retired grant error")); }); await flush(); expect(api.listConsents).toHaveBeenCalledTimes(1); expect(textOf(root)).not.toContain(t("share.webGrantedStatus", { name: found.display_name })); expect(textOf(root)).not.toContain(t("share.webGrantFailed")); expect(root.root.findAllByType("input").find(n => n.props.type === "text")!.props.value).toBe("REPLACEMENT-CODE");
});
it("clears revocation arming before a concurrent relationship reappears in the refreshed listing", async () => {
  vi.mocked(api.listConsents).mockResolvedValue([consent()]); vi.spyOn(api, "revokeConsent").mockResolvedValue(null); const root = await render(<ShareView />); await flush(); await press(root, t("share.webRevoke")); await press(root, t("share.webRevoke")); await confirm(root); vi.mocked(reauth.freshStepUp).mockClear(); await press(root, t("share.webRevoke")); expect(root.root.findAllByType("input").some(n => n.props.type === "password")).toBe(false); expect(reauth.freshStepUp).not.toHaveBeenCalled(); await press(root, t("common.cancel")); expect(surface(root)).toMatchSnapshot();
});
it("renders all past relationship names with a readable delimiter", async () => {
  vi.mocked(api.listConsents).mockResolvedValue([consent("b".repeat(32), { display_name: "Dr. Previous A", status: "revoked" }), consent("c".repeat(32), { display_name: "Dr. Previous B", status: "revoked" })]); const root = await render(<ShareView />); await flush(); expect(textOf(root)).toContain(t("share.webRevokedList", { names: "Dr. Previous A, Dr. Previous B" }));
});
it.each(["grant", "revoke", "voice"] as const)("refuses a visible sensitive control after the live vault locks: %s", async action => {
  vi.mocked(api.listConsents).mockResolvedValue([consent()]); const root = await render(<ShareView />); await flush();
  if (action === "grant") { await lookup(root); await setCheckbox(root, t("share.webFingerprintConfirm"), true); await setCheckbox(root, t("share.webDisclosureConfirm"), true); }
  else if (action === "revoke") await press(root, t("share.webRevoke"));
  vault.lock();
  if (action === "voice") await pressSwitch(root); else await press(root, t(action === "grant" ? "share.webConfirmShare" : "share.webRevoke"));
  expect(root.root.findAllByType("input").some(node => node.props.type === "password")).toBe(false); expect(reauth.freshStepUp).not.toHaveBeenCalled();
});
it("keeps the next action's password when an older grant settles after pairing changes", async () => {
  const old = deferred<ListedConsent>(); vi.spyOn(api, "grantConsent").mockReturnValue(old.promise); const root = await render(<ShareView />); await requestGrant(root); await confirm(root);
  await typeInto(root, t("share.webPairingCode"), "NEW-CODE"); await press(root, t("share.webLookUp")); await flush(); await setCheckbox(root, t("share.webFingerprintConfirm"), true); await setCheckbox(root, t("share.webDisclosureConfirm"), true); await press(root, t("share.webConfirmShare")); await typeInto(root, t("settings.reauthPasswordField"), "new action password");
  await act(async () => { old.resolve(consent()); }); await flush();
  expect(root.root.findAllByType("input").find(node => node.props.type === "password")!.props.value).toBe("new action password");
});
it("does not claim a new pairing fingerprint was copied when an older clipboard operation settles", async () => {
  const copied = deferred<void>(); vi.stubGlobal("navigator", { clipboard: { writeText: vi.fn().mockReturnValue(copied.promise) } }); const root = await render(<ShareView />); await lookup(root); await press(root, t("share.copyFingerprint"));
  await typeInto(root, t("share.webPairingCode"), "NEW-CODE"); await press(root, t("share.webLookUp")); await flush(); await act(async () => { copied.resolve(); }); await flush();
  expect(textOf(root)).toContain(t("share.copyFingerprint")); expect(textOf(root)).not.toContain(t("share.copiedFingerprint"));
});
it.each(["lookup", "grant"] as const)("preserves a newer lookup's busy state when an old operation settles: %s", async action => {
  const oldLookup = deferred<PairingLookup>(), oldGrant = deferred<ListedConsent>(); const root = await render(<ShareView />);
  if (action === "lookup") { vi.mocked(api.pairingLookup).mockReturnValueOnce(oldLookup.promise); await lookup(root); }
  else { vi.spyOn(api, "grantConsent").mockReturnValue(oldGrant.promise); await requestGrant(root); await confirm(root); }
  const current = deferred<PairingLookup>(); vi.mocked(api.pairingLookup).mockReturnValueOnce(current.promise); await typeInto(root, t("share.webPairingCode"), "NEW-CODE"); await press(root, t("share.webLookUp")); expect(isDisabled(root, t("settings.working"))).toBe(true);
  await act(async () => { if (action === "lookup") oldLookup.resolve(found); else oldGrant.resolve(consent()); }); await flush(); expect(isDisabled(root, t("settings.working"))).toBe(true); await act(async () => { current.resolve(found); }); await flush();
});
it("refuses the enabled confirmation after its vault locks without a native unhandled event failure", async () => {
  const failures: unknown[] = [], observe = (reason: unknown) => { failures.push(reason); }; process.on("unhandledRejection", observe);
  try {
    const root = await render(<ShareView />); await requestGrant(root); await typeInto(root, t("settings.reauthPasswordField"), "typed before locking"); expect(isDisabled(root, t("settings.reauthConfirm"))).toBe(false); vault.lock(); await press(root, t("settings.reauthConfirm")); await flush(); expect(failures).toEqual([]); expect(reauth.freshStepUp).not.toHaveBeenCalled();
  } finally { process.removeListener("unhandledRejection", observe); }
});
it("refuses an enabled confirmation when the unlocked keys have no verified account owner", async () => {
  const grant = vi.spyOn(api, "grantConsent").mockResolvedValue(consent()), root = await render(<ShareView />); await requestGrant(root); await typeInto(root, t("settings.reauthPasswordField"), "typed before retiring ownership"); const keys = vault.get(); vault.unlock({ authKey: keys.authKey.slice(), dataKey: keys.dataKey.slice() }); expect(isDisabled(root, t("settings.reauthConfirm"))).toBe(false); await press(root, t("settings.reauthConfirm")); await flush(); expect(grant).not.toHaveBeenCalled(); expect(reauth.freshStepUp).not.toHaveBeenCalled();
});
it("never describes a voice-scope change as a revoked therapist relationship", async () => {
  vi.mocked(api.listConsents).mockResolvedValueOnce([consent()]).mockResolvedValue([consent(undefined, { share_voice: true })]); vi.spyOn(api, "setShareVoice").mockResolvedValue({ id: consent().id, share_voice: true }); const root = await render(<ShareView />); await flush(); await pressSwitch(root); await confirm(root); expect(textOf(root)).toContain(t("share.voiceOn")); expect(textOf(root)).not.toContain(t("share.webRevokedStatus", { name: found.display_name }));
});
it("retires a computed grant wrap when the vault changes owners while retaining the data-key reference", async () => {
  const password = "fresh patient password", salt = new Uint8Array(16).fill(29), master = pbkdf2Sync(password, salt, 100_000, 32, "sha256"), authKey = new Uint8Array(hkdfSync("sha256", master, new Uint8Array(32), Buffer.from("mindpattern/auth/v1"), 32)); vault.unlock({ authKey, dataKey: new Uint8Array(32).fill(49) }, owner);
  vi.spyOn(auth, "saltFor").mockResolvedValue({ salt: Buffer.from(salt).toString("base64") }); vi.spyOn(api, "keyEnvelope").mockResolvedValue({ key_scheme: "v2", salt: Buffer.from(salt).toString("base64"), kdf_params: { algorithm: "pbkdf2-sha256", version: 1, iterations: 100_000 }, wrapped_data_key: null }); vi.mocked(reauth.freshStepUp).mockImplementation(actualFreshStepUp); const stepUp = vi.spyOn(api, "stepUp").mockResolvedValue({ proof: "actual-password-proof", action: "sharing_grant", expires_in: 120 }), grant = vi.spyOn(api, "grantConsent").mockResolvedValue(consent()), gate = deferred<void>(), began = deferred<void>(), real = sharing.wrapDataKeyForTherapist;
  vi.spyOn(sharing, "wrapDataKeyForTherapist").mockImplementation(async (...args) => { const result = await real(...args); began.resolve(); await gate.promise; return result; }); const root = await render(<ShareView />); await requestGrant(root); await confirm(root); await began.promise; const keys = vault.get(); vault.unlock({ authKey: keys.authKey.slice(), dataKey: keys.dataKey }, "another-key-owner"); await act(async () => { gate.resolve(); }); await flush(); expect(stepUp).not.toHaveBeenCalled(); expect(grant).not.toHaveBeenCalled();
});
