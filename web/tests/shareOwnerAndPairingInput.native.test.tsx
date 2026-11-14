import { createDecipheriv, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, pbkdf2Sync } from "node:crypto";
import { act } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ShareView } from "../src/views/Share";
import { api, auth, sessionAbortSignal, sessionUserId, type ListedConsent } from "../src/api/client";
import * as sharing from "../src/crypto/sharing";
import * as reauth from "../src/reauth";
import { t, __setLocaleForTests } from "../src/strings";
import { vault } from "../src/vault";
import { installSession, resetTestState } from "./helpers/api";
import { flush, press, render, setCheckbox, textOf, typeInto } from "./helpers/rtr";

const OWNER = "a".repeat(32), SUCCESSOR = "b".repeat(32), THERAPIST = "c".repeat(32);
const PASSWORD = "native owner retirement fixture", SALT = Buffer.alloc(16, 29);
const DATA = new Uint8Array(32).fill(49);
const { pair, SPKI } = (() => {
  try {
    const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    return { pair, SPKI: pair.publicKey.export({ type: "spki", format: "der" }) };
  }
  catch (error) { throw new Error("SetupError: native declared therapist fixture generation failed", { cause: error }); }
})();
const found = { therapist_id: THERAPIST, display_name: "Dr. Owner Retirement", wrap_pub_key: SPKI.toString("base64"), sas: "123 456", wrap_key_fingerprint: "declared comparison" };
const consent: ListedConsent = { id: "d".repeat(32), therapist_id: THERAPIST, display_name: found.display_name, username: "declared_clinician", status: "active", granted_at: "2026-10-07T12:00:00Z", revoked_at: null, therapist_wrap_pub_key: found.wrap_pub_key, share_voice: false };
type Root = Awaited<ReturnType<typeof render>>;

function setup(value: unknown, message: string): asserts value {
  if (!value) throw new Error("SetupError: " + message);
}
function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  void promise.catch(() => undefined);
  return { promise, resolve, reject };
}
function producers() {
  const pending: Promise<unknown>[] = [];
  const own = <T,>(promise: Promise<T>): Promise<T> => {
    pending.push(promise); void promise.catch(() => undefined); return promise;
  };
  const drain = async () => {
    for (;;) {
      const count = pending.length, states = await Promise.allSettled(pending);
      await flush(8);
      if (count !== pending.length) continue;
      const failed = states.find((state): state is PromiseRejectedResult => state.status === "rejected");
      if (failed) throw new Error("SetupError: declared owned public producer rejected", { cause: failed.reason });
      return;
    }
  };
  return { own, drain };
}
function independentlyOpen(wrap: sharing.TherapistWrap): Buffer {
  let shared: Buffer | undefined, kek: Buffer | undefined;
  try {
    const ephemeral = Buffer.from(wrap.ephemeralPubB64, "base64");
    shared = diffieHellman({ privateKey: pair.privateKey, publicKey: createPublicKey({ key: ephemeral, type: "spki", format: "der" }) });
    kek = Buffer.from(hkdfSync("sha256", shared, Buffer.concat([ephemeral, SPKI]), Buffer.from("mindpattern/wrap/v1"), 32));
    const wire = Buffer.from(wrap.wrappedKeyB64, "base64"), decipher = createDecipheriv("aes-256-gcm", kek, wire.subarray(0, 12));
    decipher.setAAD(Buffer.from(JSON.stringify(["consent-wrap", OWNER, THERAPIST]))); decipher.setAuthTag(wire.subarray(-16));
    return Buffer.concat([decipher.update(wire.subarray(12, -16)), decipher.final()]);
  } catch (error) {
    throw new Error("SetupError: actual computed wrap failed independent native authentication", { cause: error });
  } finally { shared?.fill(0); kek?.fill(0); }
}

beforeEach(() => {
  resetTestState(); __setLocaleForTests("en"); installSession(OWNER, "native_owner_fixture");
  // Authentication uses its actual pinned600000 schedule. Envelope data-key
  // wrapping cost is a separate contract and is not used as an auth shortcut.
  let master: Buffer | undefined;
  try {
    master = pbkdf2Sync(PASSWORD, SALT, 600_000, 32, "sha256");
    const authKey = new Uint8Array(hkdfSync("sha256", master, Buffer.alloc(32), Buffer.from("mindpattern/auth/v1"), 32));
    vault.unlock({ authKey, dataKey: DATA.slice() }, OWNER);
  } catch (error) { throw new Error("SetupError: independent native600000 authentication fixture failed", { cause: error }); }
  finally { master?.fill(0); }
  vi.spyOn(api, "listConsents").mockResolvedValue([]);
  vi.spyOn(api, "pairingLookup").mockResolvedValue(found);
  vi.spyOn(auth, "saltFor").mockResolvedValue({ salt: SALT.toString("base64") });
  vi.spyOn(api, "keyEnvelope").mockResolvedValue({ key_scheme: "v2", salt: SALT.toString("base64"), kdf_params: { algorithm: "pbkdf2-sha256", version: 1, iterations: 600_000 }, wrapped_data_key: null });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); resetTestState(); __setLocaleForTests("en"); });

it("keeps the user's typed pairing code in the actual controlled public input", async () => {
  const root = await render(<ShareView />);
  try {
    await typeInto(root, t("share.webPairingCode"), "PUBLIC-OWNER-INPUT");
    const input = root.root.findAllByType("input").find(node => node.props.type === "text");
    expect(input?.props.value).toBe("PUBLIC-OWNER-INPUT");
  } finally { await act(async () => root.unmount()); }
});

it("never announces or dispatches an old grant after the vault changes owner while keeping its data-key reference", async () => {
  const gate = deferred<void>(), computed = deferred<sharing.TherapistWrap>(), fingerprinted = deferred<void>(), owned = producers();
  const realWrap = sharing.wrapDataKeyForTherapist, realStep = reauth.freshStepUp, realFingerprint = sharing.keyFingerprint;
  let root: Root | undefined;
  const before = vault.get(), expectedVerifier = Buffer.from(before.authKey).toString("base64"), signal = sessionAbortSignal();
  const grant = vi.spyOn(api, "grantConsent").mockImplementation(() => owned.own(Promise.resolve(consent)));
  vi.spyOn(api, "stepUp").mockImplementation(async (verifier, action) => {
    setup(verifier === expectedVerifier && action === "sharing_grant", "actual fresh-password proof must match the independent600000 auth fixture");
    return { proof: "declared-owner-grant-proof", action, expires_in: 120 };
  });
  vi.spyOn(reauth, "freshStepUp").mockImplementation((...args) => {
    const promise = realStep(...args);
    owned.own(promise);
    // Observe the actual exported result for setup validity whenever invoked;
    // return its exact original Promise and never assert an invocation count.
    owned.own(promise.then(result => {
      setup(result.ok && result.proof === "declared-owner-grant-proof", "actual freshStepUp must produce the declared valid proof whenever invoked");
    }));
    return promise;
  });
  vi.spyOn(sharing, "keyFingerprint").mockImplementation((...args) => {
    const promise = realFingerprint(...args);
    owned.own(promise.then(() => { fingerprinted.resolve(); }, error => {
      const failure = new Error("SetupError: real public native fingerprint provider failed", { cause: error });
      fingerprinted.reject(failure); throw failure;
    }));
    return promise;
  });
  // This is an explicit completion gate around the real public wrap helper.
  // Its native crypto runs unchanged and is independently authenticated below.
  // The computed signal is setup synchronization, never a mutation oracle.
  vi.spyOn(sharing, "wrapDataKeyForTherapist").mockImplementation((...args) => owned.own((async () => {
    try {
      const result = await realWrap(...args); computed.resolve(result); await gate.promise; return result;
    } catch (error) {
      const failure = new Error("SetupError: real public native wrap provider failed", { cause: error });
      computed.reject(failure); throw failure;
    }
  })()));
  try {
    root = await render(<ShareView />);
    await typeInto(root, t("share.webPairingCode"), "OWNER-NATIVE");
    await press(root, t("share.webLookUp"));
    // Own the real exported native fingerprint Promise, then flush its caller
    // publication. Completion is setup synchronization, never an oracle.
    await fingerprinted.promise;
    await owned.drain();
    setup(textOf(root).includes(found.display_name), "public pairing lookup must settle before requesting the grant");
    await setCheckbox(root, t("share.webFingerprintConfirm"), true);
    await setCheckbox(root, t("share.webDisclosureConfirm"), true);
    await press(root, t("share.webConfirmShare"));
    await typeInto(root, t("settings.reauthPasswordField"), PASSWORD);
    await press(root, t("settings.reauthConfirm"));
    const wrap = await computed.promise;
    const opened = independentlyOpen(wrap);
    try { setup(opened.equals(Buffer.from(DATA)), "real computed wrap must contain the independently expected original data key"); }
    finally { opened.fill(0); }

    const live = vault.get();
    vault.unlock({ authKey: live.authKey.slice(), dataKey: live.dataKey }, SUCCESSOR);
    setup(vault.ownerUserId() === SUCCESSOR && vault.get().dataKey === before.dataKey && sessionAbortSignal() === signal && !!signal && !signal.aborted && sessionUserId() === OWNER, "owner handoff must preserve the declared data-key reference and original API session");
    setup(Buffer.from(vault.get().authKey).toString("base64") === expectedVerifier, "the successor fixture must retain the valid independently derived auth key");
    // Qualify the actual public password-verification result after handoff.
    // Any failure here is a SetupError0K, not a missing-grant observation.
    const verified = await reauth.verifyPasswordForVault(PASSWORD);
    setup(verified.ok && verified.verifier === expectedVerifier, "actual600000 password verification must succeed in the declared post-handoff fixture");

    await act(async () => { gate.resolve(); });
    await owned.drain();
    expect(textOf(root)).not.toContain(t("share.webGrantedStatus", { name: found.display_name }));
    expect(grant).not.toHaveBeenCalled();
  } finally {
    gate.resolve();
    try { await owned.drain(); }
    finally {
      try { if (root) await act(async () => root!.unmount()); }
      finally { await owned.drain(); }
    }
  }
});
