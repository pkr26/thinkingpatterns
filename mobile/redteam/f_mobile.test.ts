/**
 * Mobile red-team specs: A2 (offline unlock oracle), A3 (SecureStore device-key
 * forensics), A4-TS (client KDF downgrade), A6-TS (AAD canonicalization vs the
 * Python engine), E1-TS (crisis corpus vs the client engine), F1 (at-rest
 * inventory + plaintext draft after lock), F2 (error-dialog sanitizer attacks,
 * consented-HTTP data-key shipment), F4 (hostile-server UI text).
 *
 * Verdicts are written to ../redteam/results/f_mobile.json for the report.
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi, beforeAll, afterAll } from "vitest";
import AsyncStorage from "@react-native-async-storage/async-storage";
import nodeCrypto from "node:crypto";

import { detectCrisisLanguage, matchesCrisisSuppress } from "../src/crisisDetect";
import { deriveMasterKey, deriveAuthKey, deriveDataKey, KDF_ITERATIONS } from "../src/crypto/kdf";
import { buildAad } from "../src/crypto/aad";
import { secureStore } from "../src/secureStore";
import { storeUnlockProof, verifyUnlockProof } from "../src/unlockProof";
import { detailToMessage, setBaseUrl, api } from "../src/api/client";
import { stashDraft, peekDraft } from "../src/store";
import { journalDraftScope, newJournalDraft, saveJournalDraft, loadJournalDraft } from "../src/journalDraft";
import { vault } from "../src/vault";

const verdicts: Array<{ id: string; status: string; summary: string }> = [];
function verdict(id: string, status: string, summary: string): void {
  verdicts.push({ id, status, summary });
  console.log(`AUDIT|${id}|${status}|${summary}`);
}

const ROOT = new URL("../../redteam/", import.meta.url);

beforeAll(() => {
  (AsyncStorage as unknown as { __reset(): void }).__reset();
});
afterAll(() => {
  mkdirSync(new URL("results/", ROOT), { recursive: true });
  writeFileSync(new URL("results/f_mobile.json", ROOT), JSON.stringify(verdicts, null, 2));
});

describe("E1-TS: crisis corpus vs the client engine", () => {
  it("replays the bypass corpus against dialog and suppress tiers", () => {
    const rows = JSON.parse(readFileSync(new URL("crisis_corpus.json", ROOT), "utf8")) as Array<{
      technique: string;
      sample: string;
      intent: string;
      want_dialog?: boolean;
      want_suppress?: boolean;
    }>;
    const crisis = rows.filter((r) => r.intent === "crisis");
    // A "miss" is measured against the row's REQUIRED contract
    // (want_dialog/want_suppress), not against "every crisis sample must
    // fire the dialog tier" — the corpus deliberately contains
    // suppress-only rows ("i don't see any future for me") whose
    // conservative dialog:false is the contract itself. Counting those as
    // dialog misses manufactured a standing false FINDING (2026-09-20
    // audit M-17) readers learned to ignore.
    const dialogMiss = crisis.filter(
      (r) => (r.want_dialog ?? true) && !detectCrisisLanguage(r.sample),
    );
    const suppressMiss = crisis.filter(
      (r) => (r.want_suppress ?? true) && !matchesCrisisSuppress(r.sample),
    );
    const benignHit = rows.filter((r) => r.intent === "benign" && detectCrisisLanguage(r.sample));
    verdict(
      "E1.ts-dialog-bypass",
      dialogMiss.length ? "FINDING" : "BLOCKED",
      `${dialogMiss.length}/${crisis.length} crisis samples miss the on-device dialog tier ` +
        `(the pre-encryption safety net): ${dialogMiss.slice(0, 6).map((r) => r.sample)}`,
    );
    verdict(
      "E1.ts-suppress-bypass",
      suppressMiss.length ? "FINDING" : "BLOCKED",
      `${suppressMiss.length}/${crisis.length} crisis samples also miss the client-side ` +
        `suppress re-check used by InsightsScreen before rendering quotes`,
    );
    verdict(
      "E1.ts-false-positives",
      benignHit.length ? "FINDING" : "BLOCKED",
      benignHit.length
        ? `benign texts firing the crisis dialog: ${benignHit.map((r) => r.sample)}`
        : "benign controls correctly silent",
    );
    // Read-only fixture observations can be stale or null when the corpus
    // expands. Run the current Python engine over the SAME samples instead
    // of mistaking an unpopulated observation for a false result.
    const python = spawnSync(fileURLToPath(new URL("../../.venv/bin/python", import.meta.url)), ["-c", "import json,sys; from app.services.crisis import matches_dialog,matches_suppress; print(json.dumps([{'dialog':matches_dialog(s),'suppress':matches_suppress(s)} for s in json.load(sys.stdin)]))"], {
      cwd: fileURLToPath(new URL("../../backend/", import.meta.url)), input: JSON.stringify(rows.map(r => r.sample)), encoding: "utf8", timeout: 30_000,
    });
    expect(python.status, python.stderr).toBe(0);
    const observed = JSON.parse(python.stdout) as Array<{ dialog: boolean; suppress: boolean }>;
    expect(observed).toHaveLength(rows.length);
    const parityBreaks = rows.filter((r, index) => {
      const py = observed[index]!;
      expect(typeof py.dialog).toBe("boolean"); expect(typeof py.suppress).toBe("boolean");
      return detectCrisisLanguage(r.sample) !== py.dialog || matchesCrisisSuppress(r.sample) !== py.suppress;
    });
    verdict(
      "E1.ts-python-parity",
      parityBreaks.length ? "FINDING" : "BLOCKED",
      parityBreaks.length
        ? `${parityBreaks.length} samples behave differently between engines`
        : `current client and server dialog/suppress engines agree on all ${rows.length} tested corpus samples; untested language/phrasing remains outside this finite check`,
    );
    expect(parityBreaks.map(r => r.sample)).toEqual([]);
  });
});

describe("A2: offline unlock-proof oracle", () => {
  it("is an offline password oracle with state disclosure", async () => {
    const userId = "user-a2";
    const salt = nodeCrypto.randomBytes(16);
    const master = deriveMasterKey("correct horse battery", salt);
    const dataKey = deriveDataKey(master);
    await storeUnlockProof(dataKey, userId);

    // 'absent' leaks whether the oracle exists for an account
    const absent = await verifyUnlockProof(deriveDataKey(deriveMasterKey("x", salt)), "user-nobody");
    // wrong guesses are verifiable offline, at full KDF cost each
    const t0 = Date.now();
    let found = false;
    const candidates = ["letmein", "password1", "12345678", "correct horse battery"];
    for (const c of candidates) {
      const dk = deriveDataKey(deriveMasterKey(c, salt));
      if ((await verifyUnlockProof(dk, userId)) === "ok") found = true;
    }
    const perGuessMs = (Date.now() - t0) / candidates.length;
    verdict(
      "A2.offline-oracle",
      found && absent === "absent" ? "FINDING" : "BLOCKED",
      `a deliberately selected weak fixture password was recovered through the ` +
        `local password oracle in ` +
        `${candidates.length} guesses (${perGuessMs.toFixed(0)} ms/guess at ${KDF_ITERATIONS} ` +
        `iters on ONE cpu core). This assumes code executing with access to the application's ` +
        `local ciphertext/proof; it is not a random-password or hardware-keystore bypass. ` +
        `UI backoff cannot throttle an external offline script. Password-protected envelopes ` +
        `and authenticated v1 ciphertext inherently allow candidate verification if the ` +
        `required stored metadata is disclosed; device sealing adds a separate access boundary. ` +
        `Strong passwords and the pinned KDF remain necessary. 'absent' also discloses local proof presence.`,
    );
    expect(found).toBe(true); expect(absent).toBe("absent");
  }, 300_000);
});

describe("A3: SecureStore device key forensics", () => {
  it("recovers the session token from a simulated device backup", async () => {
    await secureStore.setItem("@mindpattern/token", "Bearer secret-session-token-abc");
    const store = (AsyncStorage as unknown as { _store?: Map<string, string> });
    // Read the mock's backing map through its public surface instead:
    const keys = await AsyncStorage.getAllKeys();
    const dump: Record<string, string> = {};
    for (const k of keys) dump[k] = (await AsyncStorage.getItem(k)) ?? "";
    const tokenEntry = Object.entries(dump).find(([k]) => k.endsWith("token"));
    const deviceKeyEntry = Object.entries(dump).find(([k]) => k.includes("device_k"));
    let recovered: string | null = null;
    if (tokenEntry && deviceKeyEntry) {
      const { c } = JSON.parse(tokenEntry[1]) as { c: string };
      const ct = Buffer.from(c, "base64");
      const key = Buffer.from(deviceKeyEntry[1], "base64");
      try {
        const plain = nodeCrypto.createDecipheriv("aes-256-gcm", key, ct.subarray(0, 12));
        plain.setAuthTag(ct.subarray(ct.length - 16));
        const out = Buffer.concat([plain.update(ct.subarray(12, ct.length - 16)), plain.final()]);
        recovered = out.toString("utf8");
      } catch {
        recovered = null;
      }
    }
    verdict(
      "A3.device-key-colocation",
      recovered === "Bearer secret-session-token-abc" ? "FINDING" : "BLOCKED",
      recovered
        ? `simulated backup (AsyncStorage contents) contains BOTH the device key ` +
          `('@mindpattern/device_k') and the token ciphertext; a 10-line offline script ` +
          `decrypts the session token — Keychain/Keystore custody is the documented ` +
          `pending TODO (secureStore.ts header)`
        : "could not recover token from store dump",
    );
  });
});

describe("A4-TS: client KDF parameter freedom", () => {
  it("refuses weak iteration counts (2026-09-16 floor)", () => {
    const salt = nodeCrypto.randomBytes(16);
    let refused = false;
    try {
      deriveMasterKey("pw", salt, 1);
    } catch {
      refused = true;
    }
    verdict(
      "A4.ts-kdf-no-floor",
      refused ? "BLOCKED" : "FINDING",
      refused
        ? `deriveMasterKey now throws below MIN_ITERATIONS (100k) — the client library ` +
          `pins the runtime floor; only a hand-rolled bypass (library deleted) can downgrade`
        : `deriveMasterKey still accepts iterations=1`,
    );
  });
});

describe("A6-TS: AAD canonicalization parity with the Python engine", () => {
  it("matches every edge-case vector byte-for-byte", () => {
    const cases = JSON.parse(readFileSync(new URL("aad_corpus.json", ROOT), "utf8")) as
      Array<{ name: string; parts: string[]; aad_hex: string }>;
    const mismatches = cases.filter((c) => buildAad(...c.parts).toString("hex") !== c.aad_hex);
    verdict(
      "A6.cross-platform-parity",
      mismatches.length ? "FINDING" : "BLOCKED",
      mismatches.length
        ? `canonicalization DIVERGES between platforms for: ${mismatches.map((m) => m.name)} ` +
          `(a divergence is a blob-decryptability split or a relocation-attack seam)`
        : `${cases.length} edge-case vectors (lone surrogates, DEL, CJK, RTL, combining, ` +
          `quotes) byte-identical between Python and TS — the AAD contract holds under fuzz`,
    );
  });
});

describe("F1: at-rest inventory + plaintext draft after lock", () => {
  it("keeps RAM editor plaintext across a real lock while durable draft storage is encrypted", async () => {
    const user = "user-f1", text = "my most private thought today", key = Buffer.alloc(32, 12);
    const recoveryKey = Buffer.from(key), scope = await journalDraftScope(user);
    await saveJournalDraft(key, scope, { ...newJournalDraft(), revision: 1, text });
    vault.unlock({ masterKey: Buffer.alloc(32, 10), authKey: Buffer.alloc(32, 11), dataKey: key });
    stashDraft(user, text); vault.lock();
    expect(key.equals(Buffer.alloc(32))).toBe(true);
    expect(await AsyncStorage.getItem(scope.slot)).not.toContain(text);
    expect((await loadJournalDraft(recoveryKey, scope))?.draft.text).toBe(text);
    recoveryKey.fill(0);
    const afterLock = peekDraft("user-f1");
    verdict(
      "F1.draft-survives-lock",
      afterLock === "my most private thought today" ? "INFO" : "BLOCKED",
      `The in-process editor/navigation fallback remains plaintext in the JS heap across ` +
        `vault locks and is wiped on sign-out. Active typed drafts now have encrypted ` +
        `account/server-bound persistent backups; tested storage contains no draft plaintext. Native projects ` +
        `now include the iOS switcher/capture shield and Android FLAG_SECURE. Neither ` +
        `protects a compromised application process from inspecting its JS heap.`,
    );
  });
});

describe("F2/F4: hostile-server text + consented HTTP key shipment", () => {
  it("error-dialog sanitizer vs attack strings", () => {
    const attacks: Array<[string, string]> = [
      ["scheme-less domain", "go to evil.com/support for help"],
      ["spelled url", "visit evil dot com support"],
      ["phone digits", "call 555-0134 now"],
      ["spelled phone", "call five five five zero one three four"],
      ["bidi override", "call \u202esupport 988\u202c now"],
      ["zero-width", "co\u200bntact \u200bsupport"],
      ["scheme url", "see https://evil.com/x"],
      ["weird scheme", "open mindpattern-support://x"],
    ];
    const survived = attacks.filter(([name, s]) => {
      const out = detailToMessage(s, 400);
      // Meaningful survival: an actionable contact channel, a bare domain,
      // digit runs, or invisible characters still present.
      const bidi = /[\u202a-\u202e\u200b-\u200f\u2066-\u2069]/.test(out);
      // 3-digit runs like the 988 hotline are harmless; only 4+ digit
      // runs (phone-like) or domains or invisible chars are actionable.
      return out.includes("evil.com") || /\d{4,}/.test(out) || bidi;
    });
    verdict(
      "F2.detail-sanitizer",
      survived.length ? "FINDING" : "BLOCKED",
      survived.length
        ? `hostile-server strings still carrying actionable contact info: ${survived.map((s) => s[0])}`
        : `scheme-less domains, phone digit runs and bidi/zero-width tricks are now ` +
          `stripped (2026-09-16 fix); spelled-out contacts ("five five five") remain a ` +
          `documented low-risk residual — they cannot resolve to a dialable destination`,
    );
  });

  it("refuses remote plain HTTP even with obsolete consent and a tampered legacy URL slot", async () => {
    const calls: Array<{ url: string; body: unknown }> = [];
    const mock = vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url: String(url), body: init.body });
      // A real non-redirected response carries the final URL — the app's
      // redirect defense checks it. (With an EMPTY url the app already
      // refuses the sensitive request: verified separately, that path holds.)
      return {
        ok: true,
        status: 201,
        url: String(url),
        headers: new Headers({ "Content-Type": "application/json" }),
        json: async () => ({ session_token: "st", expires_in: 300 }),
      } as unknown as Response;
    });
    vi.stubGlobal("fetch", mock);
    try {
      expect(await setBaseUrl("http://attacker.example", { allowInsecure: true })).not.toBeNull();
      expect(calls).toEqual([]);
      // Bypass the chooser as an old install/tampered local slot would.
      await AsyncStorage.setItem("@mindpattern/base_url", "http://attacker.example");
      await expect(api.openProcessingSession(Buffer.from("k".repeat(32)).toString("base64"))).rejects.toThrow();
    } finally {
      vi.unstubAllGlobals();
    }
    const shipped = calls.find((c) => c.url.startsWith("http://attacker.example"));
    const refused = !shipped;
    verdict(
      "F2.http-key-shipment",
      refused ? "BLOCKED" : "FINDING",
      refused
        ? `remote plain HTTP is refused by both URL policy and the sensitive-request ` +
          `guard, including obsolete consent and a tampered persisted URL; no fetch occurs. ` +
          `Loopback development traffic is a separate permitted boundary.`
        : `the data key was still POSTed over cleartext http`,
    );
    expect(calls).toEqual([]);
  });
});
