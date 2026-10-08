import { createDecipheriv, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, pbkdf2Sync } from "node:crypto";
import { act } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { SettingsView } from "../src/views/Settings";
import { api, auth, ApiError, clearSession } from "../src/api/client";
import * as queue from "../src/offlineQueue";
import { kv, setKvBackendForTests } from "../src/kvstore";
import { vault } from "../src/vault";
import { __setLocaleForTests, applyLanguagePref, t } from "../src/strings";
import { installSession, resetTestState, stubFetch, jsonResponse } from "./helpers/api";
import { isDisabled, press, render, textOf, textOfNode, typeInto } from "./helpers/rtr";
import { recordMood, recentMoods } from "../src/moodLog";
import { hasLocalRotation } from "../src/localRotation";
import * as localRotation from "../src/localRotation";
import * as tabLockdown from "../src/tabLockdown";

const owner = "settings-key-behavior-owner", username = "settings-key-behavior-user", password = "a-fresh-long-passphrase-7";
const params = { algorithm: "pbkdf2-sha256" as const, version: 1, iterations: 100_000 };
const oldData = new Uint8Array(new ArrayBuffer(32)).fill(63), oldAuth = new Uint8Array(new ArrayBuffer(32)).fill(65), salt = new Uint8Array(new ArrayBuffer(16)).fill(67);
type Root = Awaited<ReturnType<typeof render>>;
const flush = async () => { for (let i = 0; i < 8; i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 2)); }); };
async function settled(root: Root) { for (let i = 0; i < 2_000 && root.root.findAllByType("button").some(node => node.children.includes(t("settings.working"))); i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 2)); }); await flush(); expect(root.root.findAllByType("button").some(node => node.children.includes(t("settings.working")))).toBe(false); }
async function startChange(root: Root) { await typeInto(root, t("settings.newPasswordField"), password); await typeInto(root, t("settings.confirmPasswordField"), password); await press(root, t("settings.changePasswordButton")); await settled(root); }
function finishedNotice() { let done!: () => void; const settled = new Promise<void>(resolve => { done = resolve; }); const lockdown = vi.fn((_notice: string) => { done(); }); return { settled, lockdown }; }
async function observedCompletion(completion: Promise<void>) {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try { await Promise.race([completion, new Promise<never>((_resolve, reject) => { timeout = setTimeout(() => reject(new Error("The accepted password rotation did not publish its completion notice")), 3_000); })]); }
  finally { clearTimeout(timeout); }
}
function unwrap(wrapped: string, newSalt: string) {
  const clientSalt = Buffer.from(newSalt, "base64"), master = pbkdf2Sync(password, clientSalt, params.iterations, 32, "sha256"), kek = Buffer.from(hkdfSync("sha256", master, clientSalt, Buffer.from("mindpattern/envelope/v2"), 32)), wire = Buffer.from(wrapped, "base64");
  const decipher = createDecipheriv("aes-256-gcm", kek, wire.subarray(0, 12)); decipher.setAAD(Buffer.from(JSON.stringify({ context: "envelope", kdf_params: params, username }))); decipher.setAuthTag(wire.subarray(-16)); return Buffer.concat([decipher.update(wire.subarray(12, -16)), decipher.final()]);
}
function secretCustody() {
  const physical = new Set<Uint8Array>(), randomDataKeys: Uint8Array[] = [], realDerive = crypto.subtle.deriveBits.bind(crypto.subtle), realSet = Uint8Array.prototype.set, realRandom = crypto.getRandomValues.bind(crypto);
  // Retain the physical secret delivered by the real entropy boundary and an
  // independent copy for checking the externally wrapped replacement key.
  vi.spyOn(crypto, "getRandomValues").mockImplementation(function <T extends ArrayBufferView>(bytes: T): T {
    const result = realRandom(bytes);
    if (result instanceof Uint8Array && result.length === 32) { randomDataKeys.push(result.slice()); physical.add(result); }
    return result;
  });
  vi.spyOn(crypto.subtle, "deriveBits").mockImplementation(async (...args) => { const result = await realDerive(...args); physical.add(new Uint8Array(result)); return result; });
  // Observe physical copies of known caller secrets during the real public
  // operation. No allocation count, source line, or private call shape is pinned.
  vi.spyOn(Uint8Array.prototype, "set").mockImplementation(function (this: Uint8Array, values, offset) {
    realSet.call(this, values, offset);
    if (this !== vault.get().authKey && this !== vault.get().dataKey && this.length === 32 && (this.every(byte => byte === 63) || this.every(byte => byte === 65))) physical.add(this);
  });
  return Object.assign(() => { expect(physical.size).toBeGreaterThan(0); physical.forEach(bytes => expect(bytes).toEqual(new Uint8Array(bytes.length))); expect(vault.get().dataKey).toEqual(oldData); expect(vault.get().authKey).toEqual(oldAuth); }, { randomDataKeys });
}
beforeEach(() => {
  resetTestState(); applyLanguagePref("auto"); __setLocaleForTests("en"); installSession(owner, username); vault.unlock({ dataKey: oldData.slice(), authKey: oldAuth.slice() }, owner);
  const records = new Map<string, string>(); setKvBackendForTests({ getItem: async key => records.get(key) ?? null, setItem: async (key, value) => { records.set(key, value); }, removeItem: async key => { records.delete(key); }, keys: async () => [...records.keys()], compareAndSet: async (key, expected, value) => { if ((records.get(key) ?? null) !== expected) return false; records.set(key, value); return true; } });
  vi.spyOn(api, "meta").mockResolvedValue({ version: "1", api_version: "v1", unlock_days: 30, llm_available: false, llm_provider_name: null, llm_data_retention: null, sharing_available: true, sharing_disclosure_version: "v3", audio_available: false });
  vi.spyOn(api, "getLlmConsent").mockResolvedValue({ enabled: false, active_for_current_policy: false, llm_consent_at: null, llm_consent_disclosure: null, llm_consent_policy: null });
  vi.spyOn(api, "getVoiceConsent").mockResolvedValue({ enabled: false, active_for_current_policy: false, voice_consent_at: null, voice_consent_disclosure: null, voice_consent_policy: null });
  vi.spyOn(api, "keyEnvelope").mockResolvedValue({ key_scheme: "v2", salt: Buffer.from(salt).toString("base64"), kdf_params: params, wrapped_data_key: "existing encrypted envelope" });
  vi.spyOn(api, "accessLogPage").mockResolvedValue({ rows: [], nextCursor: null }); vi.spyOn(api, "openProcessingSession").mockResolvedValue({ session_token: "possession-proof", expires_in: 300 }); vi.spyOn(queue, "drainPendingQueueForRotation").mockResolvedValue(0); vi.spyOn(api, "listConsents").mockResolvedValue([]);
});
afterEach(() => { vi.restoreAllMocks(); setKvBackendForTests(null); applyLanguagePref("auto"); __setLocaleForTests("en"); });

it("ends the public password rotation budget before native service recovery on a fifth request", async () => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: Buffer.from(salt).toString("base64"), kdf_params: null, wrapped_data_key: null });
  await recordMood(oldData, owner, "2026-10-05", -0.5);
  let requests = 0;
  const rekey = vi.spyOn(api, "rekeyStoredData").mockImplementation(async (_old, _new, _verifier, credential) => {
    requests += 1;
    if (requests <= 4) throw new ApiError(503, "Native credential service is recovering");
    return { credential_rotated: true, operation_id: credential.operation_id };
  });
  const notice = finishedNotice(), root = await render(<SettingsView onLockdown={notice.lockdown} />);
  await flush(); const released = secretCustody(); await typeInto(root, t("settings.newPasswordField"), password); await typeInto(root, t("settings.confirmPasswordField"), password); await press(root, t("settings.changePasswordButton")); await observedCompletion(notice.settled); await flush();
  expect(rekey).toHaveBeenCalledTimes(4); expect(notice.lockdown.mock.calls[0]?.[0]).toContain("could not be confirmed"); expect(await hasLocalRotation(owner)).toBe(true); expect(await recentMoods(oldData, owner, 30)).toEqual([{ date: "2026-10-05", value: -0.5 }]); released();
});

it.each(["full rekey", "v2 password change"] as const)("releases native credential secrets before an unavailable hint provider after retired %s completion", async boundary => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: boundary === "full rekey" ? "v1" : "v2", salt: Buffer.from(salt).toString("base64"), kdf_params: params, wrapped_data_key: "existing encrypted envelope" });
  let retired = false, release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }), hint = `mindpattern.rekeyHint.${owner}`, admitted: string[] = [], write = kv.setItem.bind(kv), remove = kv.removeItem.bind(kv);
  const retire = () => { clearSession(); retired = true; };
  vi.spyOn(api, "rekeyStoredData").mockImplementation(async (_old, _new, _verifier, credential) => { retire(); return { credential_rotated: true, operation_id: credential.operation_id }; });
  vi.spyOn(api, "changePassword").mockImplementation(async () => { retire(); return null; });
  vi.spyOn(kv, "setItem").mockImplementation(async (...args) => { if (retired && args[0] === hint) { admitted.push("write"); await gate; } return write(...args); });
  vi.spyOn(kv, "removeItem").mockImplementation(async (...args) => { if (retired && args[0] === hint) { admitted.push("remove"); await gate; } return remove(...args); });
  const lockdown = vi.fn(), root = await render(<SettingsView onLockdown={lockdown} />); await flush(); const released = secretCustody();
  try {
    await typeInto(root, t("settings.newPasswordField"), password); await typeInto(root, t("settings.confirmPasswordField"), password); await press(root, t("settings.changePasswordButton"));
    for (let i = 0; i < 1000 && !retired; i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 2)); });
    await flush(); expect(retired).toBe(true); expect(admitted).toEqual([]); released(); expect(lockdown).not.toHaveBeenCalled();
  } finally { await act(async () => { release(); }); await flush(); }
});

it("keeps a retired full rotation's accepted native local completion out of the replacement view", async () => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: Buffer.from(salt).toString("base64"), kdf_params: null, wrapped_data_key: null });
  await recordMood(oldData, owner, "2026-10-05", -0.5);
  vi.spyOn(api, "rekeyStoredData").mockImplementation(async (_old, _new, _verifier, credential) => ({ credential_rotated: true, operation_id: credential.operation_id }));
  const nativeResume = localRotation.resumeLocalRotation; let completed = false;
  vi.spyOn(localRotation, "resumeLocalRotation").mockImplementation(async (...args) => { const result = await nativeResume(...args); completed = true; clearSession(); return result; });
  const lockdown = vi.fn(), root = await render(<SettingsView onLockdown={lockdown} />); await flush(); const released = secretCustody(); await startChange(root); expect(completed).toBe(true); expect(await hasLocalRotation(owner)).toBe(false); expect(lockdown).not.toHaveBeenCalled(); released();
});

it("keeps a legacy-null native v2 parameter echo bound to the pinned verifier and envelope cost", async () => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v2", salt: Buffer.from(salt).toString("base64"), kdf_params: null, wrapped_data_key: "existing encrypted envelope" });
  const pinned = { algorithm: "pbkdf2-sha256", version: 1, iterations: 600_000 }, changed = vi.spyOn(api, "changePassword").mockImplementation(async body => {
    expect(body.newKdfParams).toEqual(pinned); const nativeSalt = Buffer.from(body.newSaltB64, "base64"), master = pbkdf2Sync(password, nativeSalt, pinned.iterations, 32, "sha256"), kek = Buffer.from(hkdfSync("sha256", master, nativeSalt, Buffer.from("mindpattern/envelope/v2"), 32)), wire = Buffer.from(body.wrappedDataKeyB64, "base64"), decipher = createDecipheriv("aes-256-gcm", kek, wire.subarray(0, 12)); decipher.setAAD(Buffer.from(JSON.stringify({ context: "envelope", kdf_params: pinned, username }))); decipher.setAuthTag(wire.subarray(-16)); expect(Buffer.concat([decipher.update(wire.subarray(12, -16)), decipher.final()])).toEqual(Buffer.from(oldData)); return null;
  });
  const lockdown = vi.fn(), root = await render(<SettingsView onLockdown={lockdown} />); await flush(); await startChange(root); expect(changed).toHaveBeenCalledTimes(1); expect(lockdown).toHaveBeenCalledWith(t("settings.rotateV2SuccessNotice"));
});

it("keeps a retired accepted native upgrade receipt out of the replacement credential view", async () => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: Buffer.from(salt).toString("base64"), kdf_params: params, wrapped_data_key: null }); vi.spyOn(auth, "saltFor").mockResolvedValue({ salt: Buffer.from(salt).toString("base64") }); vi.spyOn(api, "upgradeKeyEnvelope").mockImplementation(async () => { clearSession(); return null; }); const root = await render(<SettingsView onLockdown={() => {}} />); await flush(); const released = secretCustody(); await typeInto(root, t("settings.upgradePasswordField"), password); await press(root, t("settings.upgradeButton")); await settled(root); expect(textOf(root)).not.toContain(t("settings.upgradeDoneNote")); expect(textOf(root)).toContain(t("settings.upgradeButton")); released();
});

it("releases native old-key copies before any unavailable journal read after retired hint removal", async () => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: "", kdf_params: null, wrapped_data_key: null }); let accepted = false, retired = false, reads = 0, release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }), read = kv.getItem.bind(kv), remove = kv.removeItem.bind(kv);
  vi.spyOn(api, "rekeyStoredData").mockImplementation(async (_old, _new, _verifier, credential) => { accepted = true; return { credential_rotated: true, operation_id: credential.operation_id }; });
  vi.spyOn(kv, "removeItem").mockImplementation(async (...args) => { await remove(...args); if (accepted && args[0] === `mindpattern.rekeyHint.${owner}`) { clearSession(); retired = true; } });
  vi.spyOn(kv, "getItem").mockImplementation(async (...args) => { if (retired && args[0] === `mindpattern.localRotation.${owner}`) { reads += 1; await gate; } return read(...args); }); const lockdown = vi.fn(), root = await render(<SettingsView onLockdown={lockdown} />); await flush(); const released = secretCustody();
  try { await typeInto(root, t("settings.newPasswordField"), password); await typeInto(root, t("settings.confirmPasswordField"), password); await press(root, t("settings.changePasswordButton")); for (let i = 0; i < 1000 && !retired; i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 2)); }); await flush(); expect(retired).toBe(true); expect(reads).toBe(0); released(); expect(lockdown).not.toHaveBeenCalled(); }
  finally { await act(async () => { release(); }); await flush(); }
});

it("refuses a native rekey dispatch after its actual encrypted staging receipt retires the account", async () => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: "", kdf_params: null, wrapped_data_key: null }); const stage = localRotation.stageLocalRotation; let retired = false; vi.spyOn(localRotation, "stageLocalRotation").mockImplementation(async (...args) => { const credential = await stage(...args); clearSession(); installSession("replacement-native-rekey-owner", "replacement-native-rekey-user"); vault.unlock({ authKey: new Uint8Array(32).fill(73), dataKey: new Uint8Array(32).fill(75) }, "replacement-native-rekey-owner"); retired = true; return credential; }); const fetch = stubFetch(() => jsonResponse({ detail: "Original proof cannot authorize this replacement account", code: "processing_session_expired" }, { status: 403 })), root = await render(<SettingsView onLockdown={() => {}} />); await flush();
  const { observeSecretCopies } = await import("./helpers/secretCustody"), retained = await observeSecretCopies(oldData, async () => { await startChange(root); }); expect(retired).toBe(true); expect(fetch).not.toHaveBeenCalled(); retained.copies.forEach(bytes => expect(bytes.every(byte => byte === 0)).toBe(true)); expect(vault.ownerUserId()).toBe("replacement-native-rekey-owner");
});

it("settles a publicly refused rotation without rejecting its native button continuation", async () => {
  const failures: unknown[] = [], observe = (reason: unknown) => { failures.push(reason); }; process.on("unhandledRejection", observe);
  try { vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: "", kdf_params: null, wrapped_data_key: null }); vi.mocked(queue.drainPendingQueueForRotation).mockResolvedValue(1); const root = await render(<SettingsView onLockdown={() => undefined} />); await flush(); await startChange(root); await flush(); expect(failures).toEqual([]); expect(textOf(root)).toContain(t("settings.rotateQueueBlocked")); expect(isDisabled(root, t("settings.changePasswordButton"))).toBe(false); }
  finally { process.removeListener("unhandledRejection", observe); }
});

it.each([1, "read failure"] as const)("retains the original password and all records when the rotation queue refuses to drain: %s", async state => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: "", kdf_params: null, wrapped_data_key: null });
  if (state === "read failure") vi.mocked(queue.drainPendingQueueForRotation).mockRejectedValue(new Error("encrypted queue temporarily unavailable")); else vi.mocked(queue.drainPendingQueueForRotation).mockResolvedValue(state);
  const changed = vi.spyOn(api, "rekeyStoredData"), root = await render(<SettingsView onLockdown={() => undefined} />); await flush(); await startChange(root);
  expect(textOf(root)).toContain(t("settings.rotateQueueBlocked")); expect(api.openProcessingSession).not.toHaveBeenCalled(); expect(changed).not.toHaveBeenCalled(); expect(vault.get().dataKey).toEqual(oldData);
});
it("rotates a v2 account's actual random key and includes independently decryptable wraps for only its active sharing grants", async () => {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" }), spki = pair.publicKey.export({ format: "der", type: "spki" }), active = { id: "a".repeat(32), therapist_id: "actual-therapist", display_name: "Dr. Verified", username: "verified", status: "active", therapist_wrap_pub_key: spki.toString("base64"), granted_at: "2026-10-05", revoked_at: null };
  vi.mocked(api.listConsents).mockResolvedValue([active, { ...active, id: "b".repeat(32), status: "revoked", therapist_wrap_pub_key: "" }]);
  await kv.setItem(`mindpattern.rekeyHint.${owner}`, "1"); const sent = vi.spyOn(api, "rekeyStoredData").mockImplementation(async (_old, _new, verifier, credential) => {
    expect(verifier).toBe(Buffer.from(oldAuth).toString("base64")); expect(credential.new_kdf_params).toEqual(params); expect(credential.consent_wraps).toHaveLength(1);
    const replacement = unwrap(credential.new_wrapped_data_key!, credential.new_salt); expect(replacement).not.toEqual(Buffer.from(oldData)); expect(released.randomDataKeys.some(bytes => Buffer.from(bytes).equals(replacement))).toBe(true); expect(api.openProcessingSession).toHaveBeenNthCalledWith(2, replacement.toString("base64"));
    const grant = credential.consent_wraps![0]!; expect(grant.consent_id).toBe(active.id); expect(grant.therapist_wrap_pub_key).toBe(active.therapist_wrap_pub_key);
    const ephemeral = Buffer.from(grant.ephemeral_pub, "base64"), shared = diffieHellman({ privateKey: pair.privateKey, publicKey: createPublicKey({ key: ephemeral, format: "der", type: "spki" }) }), kek = Buffer.from(hkdfSync("sha256", shared, Buffer.concat([ephemeral, spki]), Buffer.from("mindpattern/wrap/v1"), 32)), wire = Buffer.from(grant.wrapped_key, "base64");
    const decrypt = createDecipheriv("aes-256-gcm", kek, wire.subarray(0, 12)); decrypt.setAAD(Buffer.from(JSON.stringify(["consent-wrap", owner, active.therapist_id]))); decrypt.setAuthTag(wire.subarray(-16)); expect(Buffer.concat([decrypt.update(wire.subarray(12, -16)), decrypt.final()])).toEqual(replacement);
    return { credential_rotated: true, operation_id: credential.operation_id } as Awaited<ReturnType<typeof api.rekeyStoredData>>;
  });
  const notice = finishedNotice(), broadcast = vi.spyOn(tabLockdown, "broadcastTabLockdown"), root = await render(<SettingsView onLockdown={notice.lockdown} />); await flush(); const released = secretCustody(); await typeInto(root, t("settings.newPasswordField"), password); await typeInto(root, t("settings.confirmPasswordField"), password); await press(root, t("settings.rekeyHintButton")); await observedCompletion(notice.settled); await flush(); released();
  expect(sent).toHaveBeenCalledTimes(1); expect(notice.lockdown).toHaveBeenCalledWith(t("settings.rotateSuccessNotice")); expect(broadcast).toHaveBeenCalledWith("rotation"); expect(await kv.getItem(`mindpattern.rekeyHint.${owner}`)).toBeNull(); expect(root.root.findAllByType("button").some(node => node.children.includes(t("settings.working")))).toBe(false);
});

it.each([false, true])("changes a v2 password with independent verifier/envelope outputs and releases real temporary secrets: serverFails=%s", async fails => {
  const changed = vi.spyOn(api, "changePassword").mockImplementation(async body => {
    expect(body.verifierB64).toBe(Buffer.from(oldAuth).toString("base64")); expect(body.processingToken).toBe("possession-proof"); expect(body.newKdfParams).toEqual(params); expect(unwrap(body.wrappedDataKeyB64, body.newSaltB64)).toEqual(Buffer.from(oldData));
    const master = pbkdf2Sync(password, Buffer.from(body.newSaltB64, "base64"), 600_000, 32, "sha256"), expectedVerifier = Buffer.from(hkdfSync("sha256", master, new Uint8Array(32), Buffer.from("mindpattern/auth/v1"), 32)); expect(body.newVerifierB64).toBe(expectedVerifier.toString("base64")); if (fails) throw new Error("credential change unavailable"); return null;
  });
  const lockdown = vi.fn(), root = await render(<SettingsView onLockdown={lockdown} />); await flush(); const released = secretCustody(); await startChange(root); expect(changed).toHaveBeenCalledTimes(1); expect(api.openProcessingSession).toHaveBeenCalledExactlyOnceWith(Buffer.from(oldData).toString("base64")); released();
  if (fails) { expect(lockdown).not.toHaveBeenCalled(); expect(textOf(root)).toContain("credential change unavailable"); } else { expect(lockdown).toHaveBeenCalledWith(t("settings.rotateV2SuccessNotice")); expect(await kv.getItem(`mindpattern.rekeyHint.${owner}`)).toBe("1"); }
});
it.each(["success", "key mismatch", "service failure"] as const)("upgrades key protection with independently readable ciphertext and explicit verifier/probe custody: %s", async outcome => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: Buffer.from(salt).toString("base64"), kdf_params: params, wrapped_data_key: null }); vi.spyOn(auth, "saltFor").mockResolvedValue({ salt: Buffer.from(salt).toString("base64") });
  const upgrade = vi.spyOn(api, "upgradeKeyEnvelope").mockImplementation(async (wrapped, actualParams, token, verifier) => {
    expect(actualParams).toEqual(params); expect(token).toBe("possession-proof"); expect(unwrap(wrapped, Buffer.from(salt).toString("base64"))).toEqual(Buffer.from(oldData)); const master = pbkdf2Sync(password, salt, params.iterations, 32, "sha256"), expectedVerifier = Buffer.from(hkdfSync("sha256", master, new Uint8Array(32), Buffer.from("mindpattern/auth/v1"), 32)); expect(verifier).toBe(expectedVerifier.toString("base64"));
    if (outcome === "key mismatch") throw new ApiError(403, "wrong key", "envelope_key_mismatch"); if (outcome === "service failure") throw new Error("envelope service unavailable"); return null;
  });
  const root = await render(<SettingsView onLockdown={() => undefined} />); await flush(); const released = secretCustody(); await typeInto(root, t("settings.upgradePasswordField"), password); await press(root, t("settings.upgradeButton")); await settled(root); expect(upgrade).toHaveBeenCalledTimes(1); expect(auth.saltFor).toHaveBeenCalledWith(username); released();
  expect(textOf(root)).toContain(outcome === "success" ? t("settings.upgradeDoneNote") : outcome === "key mismatch" ? t("settings.upgradeKeyMismatchNote") : "envelope service unavailable"); if (outcome !== "success") expect(root.root.findAllByType("input").find(node => node.props.autoComplete === "current-password")!.props.value).toBe("");
});
it.each(["success", "retryable error", "wrong operation", "unconfirmed credential", "key mismatch", "local destination failure"] as const)("rotates v1 keys through actual encrypted local state and independent remote credentials: %s", async outcome => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: Buffer.from(salt).toString("base64"), kdf_params: null, wrapped_data_key: null }); await recordMood(oldData, owner, "2026-10-05", -2);
  vi.mocked(api.openProcessingSession).mockResolvedValueOnce({ session_token: "old-key-possession", expires_in: 300 }).mockResolvedValueOnce({ session_token: "new-key-possession", expires_in: 300 });
  let expectedNew: Uint8Array<ArrayBuffer> | undefined;
  const rekey = vi.spyOn(api, "rekeyStoredData").mockImplementation(async (oldToken, newToken, verifier, credential) => {
    expect(oldToken).toBe("old-key-possession"); expect(newToken).toBe("new-key-possession"); expect(verifier).toBe(Buffer.from(oldAuth).toString("base64"));
    const master = pbkdf2Sync(password, Buffer.from(credential.new_salt, "base64"), 600_000, 32, "sha256"), expectedAuth = Buffer.from(hkdfSync("sha256", master, new Uint8Array(32), Buffer.from("mindpattern/auth/v1"), 32)); expectedNew = new Uint8Array(hkdfSync("sha256", master, new Uint8Array(32), Buffer.from("mindpattern/data/v1"), 32)); expect(credential.new_verifier).toBe(expectedAuth.toString("base64"));
    expect(api.openProcessingSession).toHaveBeenNthCalledWith(1, Buffer.from(oldData).toString("base64")); expect(api.openProcessingSession).toHaveBeenNthCalledWith(2, Buffer.from(expectedNew).toString("base64"));
    if (outcome === "retryable error") throw new ApiError(503, "remote retryable failure"); if (outcome === "key mismatch") throw new ApiError(409, "old key refused", "rekey_key_mismatch");
    if (outcome === "local destination failure") { const actual = kv.compareAndSetForMigration; vi.spyOn(kv, "compareAndSetForMigration").mockImplementation(async (...args) => { if (args[0] === `mindpattern.moodlog.${owner}`) throw new Error("local destination unavailable"); return actual(...args); }); }
    return { credential_rotated: outcome !== "unconfirmed credential", operation_id: outcome === "wrong operation" ? "another operation" : credential.operation_id } as Awaited<ReturnType<typeof api.rekeyStoredData>>;
  });
  const lockdown = vi.fn(), root = await render(<SettingsView onLockdown={lockdown} />); await flush(); const released = secretCustody(); await startChange(root); released(); expect(lockdown).toHaveBeenCalledTimes(1);
  if (["retryable error", "wrong operation", "unconfirmed credential"].includes(outcome)) { expect(rekey).toHaveBeenCalledTimes(4); expect(lockdown.mock.calls[0]![0]).toContain("could not be confirmed"); expect(await hasLocalRotation(owner)).toBe(true); }
  else { expect(rekey).toHaveBeenCalledTimes(1); if (outcome === "success") { expect(lockdown).toHaveBeenCalledWith(t("settings.rotateSuccessNotice")); expect(await hasLocalRotation(owner)).toBe(false); expect((await recentMoods(expectedNew!, owner, 400)).map(day => [day.date, day.value])).toEqual([["2026-10-05", -1]]); } else { expect(await hasLocalRotation(owner)).toBe(true); expect(lockdown.mock.calls[0]![0]).toContain(outcome === "key mismatch" ? "could not be authenticated" : t("settings.rotateMovedLockdown")); } }
});

it.each(["v1 rotation", "v2 password", "v1 upgrade"] as const)("refuses authenticated unsupported native envelope parameters before any %s credential write", async flow => {
  const unsupported = { algorithm: "argon2id" as const, version: 1, iterations: 2, memory_kib: 19456, parallelism: 1 };
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: flow === "v2 password" ? "v2" : "v1", salt: Buffer.from(salt).toString("base64"), kdf_params: unsupported, wrapped_data_key: null });
  vi.spyOn(auth, "saltFor").mockResolvedValue({ salt: Buffer.from(salt).toString("base64") }); const changed = vi.spyOn(api, "changePassword"), upgraded = vi.spyOn(api, "upgradeKeyEnvelope"), rekeyed = vi.spyOn(api, "rekeyStoredData"), root = await render(<SettingsView onLockdown={() => {}} />); await flush();
  if (flow === "v1 upgrade") { await typeInto(root, t("settings.upgradePasswordField"), password); await press(root, t("settings.upgradeButton")); await settled(root); } else await startChange(root);
  expect(textOf(root)).toContain(t("settings.kdfUnsupportedWeb")); expect(api.openProcessingSession).not.toHaveBeenCalled(); expect(changed).not.toHaveBeenCalled(); expect(upgraded).not.toHaveBeenCalled(); expect(rekeyed).not.toHaveBeenCalled(); expect(vault.get().dataKey).toEqual(oldData);
});
it.each(["v1", "v2"] as const)("refuses a valid but mismatched public %s password pair before obtaining proof or changing keys", async scheme => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: scheme, salt: Buffer.from(salt).toString("base64"), kdf_params: params, wrapped_data_key: null });
  const root = await render(<SettingsView onLockdown={() => {}} />); await flush(); await typeInto(root, t("settings.newPasswordField"), password); await typeInto(root, t("settings.confirmPasswordField"), "another-fresh-passphrase-8"); await press(root, t("settings.changePasswordButton")); await flush(); expect(textOf(root)).toContain(t("settings.pwMismatch")); expect(api.openProcessingSession).not.toHaveBeenCalled(); expect(vault.get().dataKey).toEqual(oldData);
});
it.each(["v1", "v2"] as const)("refuses the enabled public %s credential action after the actual vault locks", async scheme => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: scheme, salt: Buffer.from(salt).toString("base64"), kdf_params: params, wrapped_data_key: null }); const errors: unknown[] = [], observe = (reason: unknown) => { errors.push(reason); }; process.on("unhandledRejection", observe);
  try { const root = await render(<SettingsView onLockdown={() => {}} />); await flush(); await typeInto(root, t("settings.newPasswordField"), password); await typeInto(root, t("settings.confirmPasswordField"), password); vault.lock(); await press(root, t("settings.changePasswordButton")); await flush(); expect(textOf(root)).toContain(t("common.sessionLocked")); expect(errors).toEqual([]); expect(api.openProcessingSession).not.toHaveBeenCalled(); }
  finally { process.removeListener("unhandledRejection", observe); }
});
it("refuses an enabled public upgrade after the native unlocked account retires", async () => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: "", kdf_params: null, wrapped_data_key: null }); const root = await render(<SettingsView onLockdown={() => {}} />); await flush(); await typeInto(root, t("settings.upgradePasswordField"), password); vault.lock(); await press(root, t("settings.upgradeButton")); await flush(); expect(textOf(root)).toContain(t("common.sessionLocked")); expect(api.openProcessingSession).not.toHaveBeenCalled();
});
it("retains a full rotation's original public pending salt while migrating its exact owner-bound legacy slot", async () => {
  const { localStore } = await import("../src/platform"), pending = Buffer.alloc(16, 43).toString("base64"), legacy = `mindpattern.rotatePendingSalt.${owner}`; localStore.set(legacy, pending); vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: "", kdf_params: null, wrapped_data_key: null });
  const rekey = vi.spyOn(api, "rekeyStoredData").mockImplementation(async (_old, _new, _verifier, credential) => { expect(credential.new_salt).toBe(pending); return { credential_rotated: true, operation_id: credential.operation_id }; });
  const root = await render(<SettingsView onLockdown={() => {}} />); await flush(); await startChange(root); expect(rekey).toHaveBeenCalledTimes(1); expect(localStore.get(legacy)).toBeNull();
});
it("shows an actionable refusal when an active sharing grant has no authenticated current key", async () => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: "", kdf_params: null, wrapped_data_key: null }); vi.mocked(api.listConsents).mockResolvedValue([{ id: "a".repeat(32), therapist_id: "actual-therapist", display_name: "Dr. Retained", username: "retained", status: "active", therapist_wrap_pub_key: "", granted_at: "2026-10-05", revoked_at: null }]); const root = await render(<SettingsView onLockdown={() => {}} />); await flush(); await startChange(root);
  expect(textOf(root)).toContain("An active sharing grant has no current public key. Repair it before rotating encryption keys."); expect(vault.get().dataKey).toEqual(oldData);
});

it("does not lock a replacement account when a committed v2 password change's native hint write finishes late", async () => {
  const records = new Map<string, string>(), hint = `mindpattern.rekeyHint.${owner}`, replacement = "replacement-password-owner";
  vi.spyOn(api, "changePassword").mockResolvedValue(null); const lockdown = vi.fn(), root = await render(<SettingsView onLockdown={lockdown} />); await flush();
  setKvBackendForTests({ getItem: async key => records.get(key) ?? null, setItem: async (key, value) => { records.set(key, value); if (key === hint) { clearSession(); installSession(replacement, "replacement-password-user"); vault.unlock({ dataKey: new Uint8Array(32).fill(77), authKey: new Uint8Array(32).fill(79) }, replacement); } }, removeItem: async key => { records.delete(key); }, keys: async () => [...records.keys()] });
  await startChange(root); expect(api.changePassword).toHaveBeenCalledTimes(1); expect(await kv.getItem(hint)).toBe("1"); expect(lockdown).not.toHaveBeenCalled(); expect(vault.ownerUserId()).toBe(replacement); expect(vault.get().dataKey).toEqual(new Uint8Array(32).fill(77));
});
it("does not lock a replacement vault when a full rotation's accepted native hint removal finishes late", async () => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: "", kdf_params: null, wrapped_data_key: null });
  let accepted = false;
  vi.spyOn(api, "rekeyStoredData").mockImplementation(async (_old, _new, _verifier, credential) => { accepted = true; return { credential_rotated: true, operation_id: credential.operation_id } as Awaited<ReturnType<typeof api.rekeyStoredData>>; });
  await kv.setItem(`mindpattern.rekeyHint.${owner}`, "1"); const removed = kv.removeItem.bind(kv); let replaced = false;
  vi.spyOn(kv, "removeItem").mockImplementation(async (...args) => { await removed(...args); if (accepted && args[0] === `mindpattern.rekeyHint.${owner}`) { replaced = true; clearSession(); installSession("replacement-full-rotation-owner", "replacement-full-rotation-user"); vault.unlock({ authKey: new Uint8Array(32).fill(75), dataKey: new Uint8Array(32).fill(77) }, "replacement-full-rotation-owner"); } });
  const lockdown = vi.fn(), root = await render(<SettingsView onLockdown={lockdown} />); await flush(); await typeInto(root, t("settings.newPasswordField"), password); await typeInto(root, t("settings.confirmPasswordField"), password); await press(root, t("settings.changePasswordButton"));
  for (let i = 0; i < 1000 && !replaced; i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 2)); }); expect(replaced).toBe(true); await flush(); expect(api.rekeyStoredData).toHaveBeenCalledTimes(1); expect(lockdown).not.toHaveBeenCalled(); expect(vault.ownerUserId()).toBe("replacement-full-rotation-owner"); expect(vault.get().dataKey).toEqual(new Uint8Array(32).fill(77));
});

it.each(["v1 old proof", "v1 new proof", "v2 proof", "upgrade proof", "v2 native wrap", "upgrade native wrap", "v1 native derivation"] as const)("retires a credential operation at its accepted %s receipt and erases its own keys", async boundary => {
  const scheme = boundary.startsWith("v2") ? "v2" : "v1", replacement = "replacement-native-proof-owner";
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: scheme, salt: Buffer.from(salt).toString("base64"), kdf_params: params, wrapped_data_key: scheme === "v2" ? "existing encrypted envelope" : null });
  vi.spyOn(auth, "saltFor").mockResolvedValue({ salt: Buffer.from(salt).toString("base64") });
  const changed = vi.spyOn(api, "changePassword").mockResolvedValue(null), upgraded = vi.spyOn(api, "upgradeKeyEnvelope").mockResolvedValue(null), rekeyed = vi.spyOn(api, "rekeyStoredData"), lockdown = vi.fn();
  const root = await render(<SettingsView onLockdown={lockdown} />); await flush();
  const physical = new Set<Uint8Array>(), realSet = Uint8Array.prototype.set, realDerive = crypto.subtle.deriveBits.bind(crypto.subtle), realEncrypt = crypto.subtle.encrypt.bind(crypto.subtle);
  let retired = false, proofs = 0;
  const retire = () => { retired = true; clearSession(); installSession(replacement, "replacement-native-proof-user"); vault.unlock({ authKey: new Uint8Array(32).fill(75), dataKey: new Uint8Array(32).fill(77) }, replacement); };
  vi.spyOn(Uint8Array.prototype, "set").mockImplementation(function (this: Uint8Array, values, offset) { realSet.call(this, values, offset); if (this.length === 32 && this !== vault.get().dataKey && this !== vault.get().authKey && (this.every(byte => byte === 63) || this.every(byte => byte === 65))) physical.add(this); });
  vi.spyOn(crypto.subtle, "deriveBits").mockImplementation(async (...args) => { const result = await realDerive(...args); physical.add(new Uint8Array(result)); const algorithm = args[0] as Pbkdf2Params; if (boundary === "v1 native derivation" && algorithm.name === "PBKDF2" && algorithm.iterations === params.iterations) retire(); return result; });
  vi.mocked(api.openProcessingSession).mockImplementation(async () => { proofs += 1; if ((boundary === "v1 old proof" && proofs === 1) || (boundary === "v1 new proof" && proofs === 2) || boundary === "v2 proof" || boundary === "upgrade proof") retire(); return { session_token: `accepted-native-proof-${proofs}`, expires_in: 300 }; });
  vi.spyOn(crypto.subtle, "encrypt").mockImplementation(async (...args) => { const result = await realEncrypt(...args); if (boundary.endsWith("native wrap")) retire(); return result; });
  if (boundary.startsWith("upgrade")) { await typeInto(root, t("settings.upgradePasswordField"), password); await press(root, t("settings.upgradeButton")); await settled(root); } else await startChange(root);
  expect(retired).toBe(true); expect(textOf(root)).toContain(t("common.sessionLocked")); expect(changed).not.toHaveBeenCalled(); expect(upgraded).not.toHaveBeenCalled(); expect(rekeyed).not.toHaveBeenCalled(); expect(lockdown).not.toHaveBeenCalled();
  if (boundary === "v1 old proof") expect(proofs).toBe(1); if (boundary === "v1 new proof") expect(api.listConsents).not.toHaveBeenCalled(); if (boundary === "v1 native derivation") expect(proofs).toBe(0);
  expect(physical.size).toBeGreaterThan(0); physical.forEach(bytes => expect(bytes).toEqual(new Uint8Array(bytes.length))); expect(vault.ownerUserId()).toBe(replacement); expect(vault.get().dataKey).toEqual(new Uint8Array(32).fill(77)); expect(vault.get().authKey).toEqual(new Uint8Array(32).fill(75));
});

it.each(["v1", "v2"] as const)("starts all public %s credential fields empty after the actual scheme result arrives", async scheme => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: scheme, salt: Buffer.from(salt).toString("base64"), kdf_params: params, wrapped_data_key: null }); const root = await render(<SettingsView onLockdown={() => {}} />); await flush(); expect(root.root.findAllByType("input").map(node => node.props.value)).toEqual(scheme === "v1" ? ["", "", "", ""] : ["", "", ""]);
});

it.each(["v1", "v2"] as const)("refuses the public %s weak-password action before deriving or dispatching credentials", async scheme => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: scheme, salt: "", kdf_params: null, wrapped_data_key: null }); const root = await render(<SettingsView onLockdown={() => {}} />); await flush(); const derive = vi.spyOn(crypto.subtle, "deriveBits"); await typeInto(root, t("settings.newPasswordField"), "aaaaaaaaaaaa"); await typeInto(root, t("settings.confirmPasswordField"), "aaaaaaaaaaaa"); await press(root, t("settings.changePasswordButton")); await flush(); expect(textOf(root)).toContain(t("login.policyVarietyWeb")); expect(derive).not.toHaveBeenCalled(); expect(api.openProcessingSession).not.toHaveBeenCalled();
});

it.each(["absent", "invalid"] as const)("forgets prior declared costs when the public retry returns %s envelope parameters before a native upgrade", async state => {
  vi.mocked(api.meta).mockRejectedValueOnce(new ApiError(503, "Metadata briefly unavailable")); vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: Buffer.from(salt).toString("base64"), kdf_params: params, wrapped_data_key: null }); const root = await render(<SettingsView onLockdown={() => {}} />); await flush();
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: Buffer.from(salt).toString("base64"), kdf_params: state === "absent" ? null : { ...params, version: 91 }, wrapped_data_key: null }); await press(root, t("settings.llmRetry")); await flush(); vi.spyOn(auth, "saltFor").mockResolvedValue({ salt: Buffer.from(salt).toString("base64") });
  const pinned = { algorithm: "pbkdf2-sha256", version: 1, iterations: 600_000 }, upgraded = vi.spyOn(api, "upgradeKeyEnvelope").mockImplementation(async (wrapped, actualParams) => { expect(actualParams).toEqual(pinned); const master = pbkdf2Sync(password, salt, 600_000, 32, "sha256"), kek = Buffer.from(hkdfSync("sha256", master, salt, Buffer.from("mindpattern/envelope/v2"), 32)), wire = Buffer.from(wrapped, "base64"), decipher = createDecipheriv("aes-256-gcm", kek, wire.subarray(0, 12)); decipher.setAAD(Buffer.from(JSON.stringify({ context: "envelope", kdf_params: pinned, username }))); decipher.setAuthTag(wire.subarray(-16)); expect(Buffer.concat([decipher.update(wire.subarray(12, -16)), decipher.final()])).toEqual(Buffer.from(oldData)); return null; });
  await typeInto(root, t("settings.upgradePasswordField"), password); await press(root, t("settings.upgradeButton")); await settled(root); expect(upgraded).toHaveBeenCalledTimes(1); expect(textOf(root)).toContain(t("settings.upgradeDoneNote"));
});

it("refuses a fresh full-rotation envelope outage without treating the unavailable server as a legacy backend", async () => {
  vi.mocked(api.keyEnvelope).mockResolvedValueOnce({ key_scheme: "v1", salt: "", kdf_params: null, wrapped_data_key: null }).mockRejectedValue(new ApiError(503, "Envelope service unavailable")); const root = await render(<SettingsView onLockdown={() => {}} />); await flush(); await startChange(root); expect(textOf(root)).toContain(t("settings.rotateFailed")); expect(api.openProcessingSession).not.toHaveBeenCalled();
});

it("reports a native upgrade service outage without inventing a key-mismatch refusal", async () => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: "", kdf_params: params, wrapped_data_key: null }); vi.spyOn(auth, "saltFor").mockResolvedValue({ salt: Buffer.from(salt).toString("base64") }); vi.spyOn(api, "upgradeKeyEnvelope").mockRejectedValue(new ApiError(503, "Upgrade unavailable")); const root = await render(<SettingsView onLockdown={() => {}} />); await flush(); await typeInto(root, t("settings.upgradePasswordField"), password); await press(root, t("settings.upgradeButton")); await settled(root); expect(textOf(root)).toContain(t("errors.serverError")); expect(textOf(root)).not.toContain(t("settings.upgradeKeyMismatchNote"));
});

it("retains its live account after a native rekey proof refusal without inventing a committed migration", async () => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: "v1", salt: "", kdf_params: null, wrapped_data_key: null }); vi.spyOn(api, "rekeyStoredData").mockRejectedValue(new ApiError(403, "Processing proof expired", "processing_session_expired")); const lockdown = vi.fn(), root = await render(<SettingsView onLockdown={lockdown} />); await flush(); await startChange(root); expect(lockdown).not.toHaveBeenCalled(); expect(textOf(root)).toContain(t("errors.forbidden")); expect(vault.get().dataKey).toEqual(oldData);
});

it.each(["v1", "v2", "v2 hint", "upgrade"] as const)("labels each native pending credential control honestly in its own %s card", async flow => {
  let release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; });
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: flow === "v2" || flow === "v2 hint" ? "v2" : "v1", salt: Buffer.from(salt).toString("base64"), kdf_params: params, wrapped_data_key: "existing encrypted envelope" });
  if (flow === "v2 hint") await kv.setItem(`mindpattern.rekeyHint.${owner}`, "1");
  const root = await render(<SettingsView onLockdown={() => {}} />); await flush();
  if (flow === "upgrade") vi.spyOn(auth, "saltFor").mockImplementationOnce(async () => { await gate; throw new ApiError(503, "Native credential preflight refused"); });
  else vi.mocked(api.keyEnvelope).mockImplementationOnce(async () => { await gate; throw new ApiError(503, "Native credential preflight refused"); });
  try {
    if (flow === "upgrade") { await typeInto(root, t("settings.upgradePasswordField"), password); await press(root, t("settings.upgradeButton")); }
    else { await typeInto(root, t("settings.newPasswordField"), password); await typeInto(root, t("settings.confirmPasswordField"), password); await press(root, t(flow === "v2 hint" ? "settings.rekeyHintButton" : "settings.changePasswordButton")); }
    await flush(); const title = t(flow === "upgrade" ? "settings.upgradeTitle" : "settings.rotateTitle"), card = root.root.findAllByType("section").find(section => section.findAllByType("h2").some(node => textOfNode(node) === title))!;
    expect(card.findAllByType("button").map(textOfNode)).toEqual(flow === "v2 hint" ? [t("settings.working"), t("settings.rekeyHintDismiss"), t("settings.working")] : [t("settings.working")]); expect(card.findAllByType("button").every(button => button.props.disabled === true && button.props.onClick === undefined)).toBe(true); expect(root.root.findAllByType("div").filter(node => node.props.role === "alert")).toHaveLength(0);
  } finally { await act(async () => { release(); }); await settled(root); }
});

it.each(["full drain", "full v2 envelope", "v2 envelope", "v2 possession", "upgrade possession"] as const)("releases native owned secrets without dispatching unavailable crypto after retired %s acceptance", async boundary => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: boundary.startsWith("v2") || boundary === "full v2 envelope" ? "v2" : "v1", salt: Buffer.from(salt).toString("base64"), kdf_params: params, wrapped_data_key: "existing encrypted envelope" }); if (boundary === "full v2 envelope") await kv.setItem(`mindpattern.rekeyHint.${owner}`, "1");
  const root = await render(<SettingsView onLockdown={() => {}} />); await flush(); let retired = false, release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; });
  const derive = crypto.subtle.deriveBits.bind(crypto.subtle), encrypt = crypto.subtle.encrypt.bind(crypto.subtle); const later: string[] = [];
  vi.spyOn(crypto.subtle, "deriveBits").mockImplementation(async (...args) => { const result = await derive(...args); if (retired) { later.push("derive"); await gate; } return result; });
  vi.spyOn(crypto.subtle, "encrypt").mockImplementation(async (...args) => { const result = await encrypt(...args); if (retired) { later.push("encrypt"); await gate; } return result; });
  const retire = () => { clearSession(); retired = true; };
  if (boundary === "full drain") vi.mocked(queue.drainPendingQueueForRotation).mockImplementationOnce(async () => { retire(); return 0; });
  else if (boundary === "v2 envelope" || boundary === "full v2 envelope") vi.mocked(api.keyEnvelope).mockImplementationOnce(async () => { retire(); return { key_scheme: "v2", salt: Buffer.from(salt).toString("base64"), kdf_params: params, wrapped_data_key: "existing encrypted envelope" }; });
  else vi.mocked(api.openProcessingSession).mockImplementationOnce(async () => { retire(); return { session_token: "accepted-native-possession-proof", expires_in: 300 }; });
  if (boundary === "upgrade possession") vi.spyOn(auth, "saltFor").mockResolvedValue({ salt: Buffer.from(salt).toString("base64") });
  const { observeSecretCopies } = await import("./helpers/secretCustody");
  try { const retained = await observeSecretCopies(oldData, async () => {
    if (boundary === "upgrade possession") { await typeInto(root, t("settings.upgradePasswordField"), password); await press(root, t("settings.upgradeButton")); for (let i = 0; i < 1000 && !retired; i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 2)); }); }
    else { await typeInto(root, t("settings.newPasswordField"), password); await typeInto(root, t("settings.confirmPasswordField"), password); await press(root, t(boundary === "full v2 envelope" ? "settings.rekeyHintButton" : "settings.changePasswordButton")); }
    await flush(); expect(retired).toBe(true); return undefined;
  }); expect(retained.copies.length).toBeGreaterThan(0); retained.copies.forEach(bytes => expect(bytes.every(byte => byte === 0)).toBe(true)); expect(later).toEqual([]); expect(textOf(root)).toContain(t("common.sessionLocked")); }
  finally { await act(async () => { release(); }); await settled(root); }
});

it.each(["full", "v2", "upgrade"] as const)("gives localized retry guidance for an unclassified native %s credential refusal", async flow => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ key_scheme: flow === "v2" ? "v2" : "v1", salt: Buffer.from(salt).toString("base64"), kdf_params: params, wrapped_data_key: "existing encrypted envelope" });
  if (flow === "full") vi.spyOn(api, "rekeyStoredData").mockRejectedValue(new ApiError(422, "Unclassified current credential refusal", "credential_validation_failed"));
  else if (flow === "v2") vi.spyOn(api, "changePassword").mockRejectedValue(new ApiError(422, "Unclassified current password refusal", "credential_validation_failed"));
  else { vi.spyOn(auth, "saltFor").mockResolvedValue({ salt: Buffer.from(salt).toString("base64") }); vi.spyOn(api, "upgradeKeyEnvelope").mockRejectedValue(new ApiError(422, "Unclassified current envelope refusal", "credential_validation_failed")); }
  const lockdown = vi.fn(), root = await render(<SettingsView onLockdown={lockdown} />); await flush();
  if (flow === "upgrade") { await typeInto(root, t("settings.upgradePasswordField"), password); await press(root, t("settings.upgradeButton")); await settled(root); }
  else await startChange(root);
  expect(textOf(root)).toContain(t(flow === "upgrade" ? "settings.upgradeFailedNote" : "settings.rotateFailed")); expect(textOf(root)).not.toContain("Unclassified current"); expect(lockdown).not.toHaveBeenCalled(); expect(vault.get().dataKey).toEqual(oldData);
});
