/** Native Node DOM/task consumer contract. An input task looks up the current
 * playback control after a same-chart commit and before its NormalPriority
 * passive reset. No input runs during commit and no prior handler is retained.
 * This is an explicit Node DOM scheduler contract, not a physical-browser claim. */
import { createRequire } from "node:module";
import { createServer } from "node:http";
import { IDBFactory } from "fake-indexeddb";
import { act, useLayoutEffect } from "react";
import { expect, it, vi } from "vitest";
import { api, ApiError, clearSession, setSession, type Patient } from "../src/api";
import * as cryptography from "../src/crypto";
import { drainPortalDraftWritesForTests } from "../src/noteDrafts";
import { resetKvConnectionForTests, setKvBackendForTests } from "../src/kvstore";
import { PatientView } from "../src/views/PatientView";
import { authenticatedFixture, OWNER, PASSWORD, USERNAME } from "./helpers/prospectiveNativeChart";

// jsdom is an installed provider. The explicit Node host keeps WebCrypto and
// BufferSource objects in their actual Node realm while supplying genuine DOM.
const { JSDOM } = createRequire(import.meta.url)("jsdom") as { JSDOM: new (html: string, options: { url: string }) => { window: Window & typeof globalThis } };
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
async function finite<T>(promise: Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([promise, new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error(`SetupError: native audio task producer deadline: ${label}`)), 15_000); })]); }
  finally { if (timer) clearTimeout(timer); }
}

const cases = [
  { name: "active audio grant", notesOnly: false, keyless: false, input: "play recording" },
  { name: "notes-only audio refusal", notesOnly: true, keyless: false, input: "play recording" },
  { name: "keyless evidence diagnostic while refresh is pending", notesOnly: false, keyless: true, input: "See the evidence" },
] as const;
it.each(cases)("a post-commit native consent task preserves $name", async ({ notesOnly, keyless, input }) => {
  vi.useRealTimers(); const flags = globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }; const oldAct = flags.IS_REACT_ACT_ENVIRONMENT; flags.IS_REACT_ACT_ENVIRONMENT = true;
  const account = authenticatedFixture(false, false, false, false);
  const master = await cryptography.deriveMasterKey(PASSWORD, cryptography.fromBase64("AAECAwQFBgcICQoLDA0ODw=="));
  const keys = await cryptography.derivePortalKeys(master); master.fill(0);
  const opened = await cryptography.unlockWrapPrivateKeyWithNotesKey(keys.wrapKek, account.envelope, USERNAME); keys.wrapKek.fill(0);
  const session = { userId: OWNER, username: USERNAME, noteKey: keys.noteKey, noteKeyV2: opened.noteKeyV2, privateKey: opened.privateKey, publicKeyB64: account.publicKey };
  // The real per-chart quota is1000 notes. Keep a legitimate populated pattern
  // in the DOM so the committed update can yield before NormalPriority effects.
  const rows = await Promise.all(Array.from({ length: 1000 }, async (_, index) => {
    const id = `native-audio-handoff-note-${index}`;
    return { ...account.target, id, client_note_id: id, pattern_pid: keyless ? null : "temporal:native-evidence", blob: (await cryptography.encryptNote(session.noteKeyV2, OWNER, account.patient.user_id, id, `Authenticated handoff note ${index}`)).blobB64 };
  }));
  const reads: string[] = [], faults: unknown[] = [], handlers: Promise<void>[] = [], producers: Array<{ label: string; promise: Promise<unknown> }> = [], restorers: Array<() => void> = [];
  let insightCalls = 0, insightHeld = false, holdReplacementInsights = false, replacementInsightStarted = false, releaseInsight = () => {};
  let insightCompletion = Promise.resolve();
  const server = createServer((request, response) => {
    const handling = (async () => {
      try {
        const url = new URL(request.url ?? "/", "http://127.0.0.1"), path = url.pathname;
        if (request.headers.authorization !== "Bearer native-audio-handoff") throw new Error("SetupError: native audio route lacks its current authenticated owner");
        let value: unknown, status = 200;
        if (path.endsWith("/insights")) { insightCalls++; if (keyless && holdReplacementInsights) { insightHeld = true; await insightCompletion; } value = account.insights; }
        else if (path.endsWith("/notes")) { const offset = Number(url.searchParams.get("offset") ?? "0"); value = rows.slice(offset, offset + 100); response.setHeader("X-Notes-Revision", "7"); if (offset + 100 < rows.length) response.setHeader("X-Next-Offset", String(offset + 100)); }
        else if (path.endsWith("/measures")) value = [];
        else if (path.endsWith("/entries")) value = account.entries;
        else if (path.includes("/audio/")) { reads.push(path); if (notesOnly) { status = 403; value = { code: "consent_voice_share_required", detail: "voice sharing ended" }; } else value = account.audio; }
        else throw new Error(`SetupError: unowned native audio route: ${path}`);
        response.writeHead(status, { "Content-Type": "application/json" }); response.end(JSON.stringify(value));
      } catch (error) { faults.push(error); response.writeHead(500, { "Content-Type": "application/json" }); response.end("{}"); }
    })(); handlers.push(handling);
  });
  await finite(new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); }), "owned native listener");
  const address = server.address(); if (!address || typeof address === "string") throw new Error("SetupError: native audio listener has no address");
  const origin = `http://127.0.0.1:${address.port}`, dom = new JSDOM("<!doctype html><html><body></body></html>", { url: origin });
  const own = (label: string, promise: Promise<unknown>) => { producers.push({ label, promise }); void promise.catch(() => undefined); return promise; };
  const databases: IDBDatabase[] = [], factory = new IDBFactory(), open = factory.open;
  factory.open = (...args: Parameters<IDBFactory["open"]>) => { const request = open.apply(factory, args); request.addEventListener("success", () => databases.push(request.result)); return request; };
  vi.stubGlobal("window", dom.window); vi.stubGlobal("document", dom.window.document); vi.stubGlobal("navigator", dom.window.navigator); vi.stubGlobal("HTMLElement", dom.window.HTMLElement); vi.stubGlobal("indexedDB", factory);
  resetKvConnectionForTests(); setKvBackendForTests(null); setSession("native-audio-handoff", origin);
  for (const name of ["patientInsights", "notes", "patientMeasures", "patientEntries", "patientAudio"] as const) {
    const original = api[name]; const observer = vi.spyOn(api, name).mockImplementation(((...args: never[]) => {
      if (name === "patientInsights" && holdReplacementInsights) replacementInsightStarted = true;
      return own(`api.${name}`, (original as (...args: never[]) => Promise<unknown>)(...args));
    }) as never); restorers.push(() => observer.mockRestore());
  }
  for (const name of ["unwrapPatientDataKey", "decryptInsights", "decryptEntry", "decryptNoteAny", "decryptAudio"] as const) {
    const original = cryptography[name]; const observer = vi.spyOn(cryptography, name).mockImplementation(((...args: never[]) => own(`crypto.${name}`, (original as (...args: never[]) => Promise<unknown>)(...args))) as never); restorers.push(() => observer.mockRestore());
  }
  const { createRoot } = await import("react-dom/client"), container = document.createElement("div"); document.body.append(container); const root = createRoot(container);
  let layoutFinished = false;
  type Phase = { separateNativeTask: boolean; committedNotesOnly: boolean; currentInputControl: boolean; currentRefreshStarted?: boolean };
  let phase: Phase | undefined;
  const admissionAttempts: Phase[] = [];
  function Chart({ row, queueInput }: { row: Patient; queueInput: boolean }) {
    useLayoutEffect(() => { if (queueInput) layoutFinished = true; }, [row, queueInput]);
    return <PatientView patient={row} session={session} onBack={() => {}} />;
  }
  // A ready input timer models a separately queued native input task. React's
  // NormalPriority passive work may win on a given turn, so only an observed
  // current-DOM window admits the input. Retry the public handoff, never an
  // assertion or a saved callback, and retain each admission observation.
  async function deliverCurrentInput(): Promise<boolean> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const original = new Promise<boolean>((resolve, reject) => {
      const inputTask = () => {
        if (!layoutFinished) { timer = setTimeout(inputTask, 0); return; }
        try {
          const button = [...container.querySelectorAll("button")].find(node => node.textContent === input);
          // The keyless diagnostic belongs after the current refresh has
          // synchronously cleared the old banner, while its real response is
          // pending. An earlier click may legitimately be cleared by that reset.
          if (keyless && !replacementInsightStarted && button && !button.disabled) { timer = setTimeout(inputTask, 0); return; }
          phase = { separateNativeTask: layoutFinished, committedNotesOnly: (container.textContent ?? "").includes("sharing ended"), currentInputControl: button !== undefined && !button.disabled, ...(keyless ? { currentRefreshStarted: replacementInsightStarted } : {}) };
          admissionAttempts.push(phase);
          const admitted = phase.separateNativeTask && phase.currentInputControl && phase.committedNotesOnly === notesOnly && (!keyless || replacementInsightStarted);
          if (admitted) button!.click();
          resolve(admitted);
        } catch (error) { reject(error); }
      };
      timer = setTimeout(inputTask, 0);
    });
    try { return await finite(original, "post-commit current DOM input task"); }
    finally { if (timer) clearTimeout(timer); }
  }
  async function drain() {
    for (;;) {
      const current = [...producers], count = handlers.length;
      await act(async () => {
        const results = await finite(Promise.allSettled(current.map(row => row.promise)), "identical native API/crypto Promises");
        for (const [index, result] of results.entries()) if (result.status === "rejected" && !(current[index]!.label === "api.patientAudio" && result.reason instanceof ApiError && result.reason.status === 403)) throw new Error("SetupError: unexpected original native audio producer rejection", { cause: result.reason });
        await finite(Promise.all(handlers), "native HTTP handlers"); await turn();
      });
      if (current.length === producers.length && count === handlers.length) return;
    }
  }
  async function complete(label: string, predicate: () => boolean) {
    const deadline = Date.now() + 15_000;
    while (!predicate()) { if (faults.length) throw new Error("SetupError: owned native HTTP fault", { cause: faults[0] }); if (Date.now() >= deadline) throw new Error(`SetupError: actual native audio producer did not complete: ${label}`); await act(async () => { await new Promise(resolve => setTimeout(resolve, 5)); }); }
  }
  try {
    await act(async () => root.render(<Chart row={account.patient} queueInput={false} />));
    await complete("authenticated patterns", () => (container.textContent ?? "").includes("See the evidence"));
    if (!keyless) await act(async () => [...container.querySelectorAll("button")].find(button => button.textContent === "See the evidence")!.click());
    await complete("authenticated bounded chart before consent handoff", () => (container.textContent ?? "").includes(keyless ? "See the evidence" : "Authenticated audio evidence") && (container.textContent ?? "").includes("Authenticated handoff note 999"));
    await drain();
    let admitted = false;
    for (let attempt = 0; attempt < 10 && !admitted; attempt++) {
      layoutFinished = false; insightHeld = false; holdReplacementInsights = keyless; replacementInsightStarted = false;
      insightCompletion = new Promise<void>(resolve => { releaseInsight = resolve; });
      // Leave this default-lane commit outside act: act would force its passive
      // reset before a separate native task can model the current input queue.
      flags.IS_REACT_ACT_ENVIRONMENT = false;
      const delivered = deliverCurrentInput();
      root.render(<Chart row={keyless ? { ...account.patient, wrapped_key: null, username: "Native keyless current" } : notesOnly ? { ...account.patient, status: "revoked", revoked_at: "2026-10-21T00:00:00Z" } : account.patient} queueInput />);
      admitted = await delivered; flags.IS_REACT_ACT_ENVIRONMENT = true;
      if (!admitted) {
        releaseInsight(); holdReplacementInsights = false; await drain();
        await act(async () => root.render(<Chart row={account.patient} queueInput={false} />));
        await complete("authenticated chart restored after unadmitted native task", () => (container.textContent ?? "").includes("See the evidence") && (container.textContent ?? "").includes("Authenticated handoff note 999"));
        if (!keyless) await act(async () => [...container.querySelectorAll("button")].find(button => button.textContent === "See the evidence")!.click());
        await complete("public evidence restored before another native handoff", () => (container.textContent ?? "").includes(keyless ? "See the evidence" : "Authenticated audio evidence"));
        await drain();
      }
    }
    process.stdout.write(`Native current-DOM task admission ${JSON.stringify({ name: input, keyless, notesOnly, attempts: admissionAttempts })}\n`);
    if (!admitted) throw new Error("SetupError: no separate native input task observed the committed handoff before passive reset", { cause: admissionAttempts });
    if (keyless) {
      await complete("genuine replacement insights HTTP response held", () => insightHeld); await act(async () => { await turn(); });
      expect(container.textContent).toContain("Native keyless current");
      expect(container.querySelector("[role=alert]")?.textContent ?? "", "Refused evidence must explain the missing consent key while the real current refresh remains pending").toContain("this consent carries no key material");
      releaseInsight();
    }
    await drain();
    expect(phase).toEqual({ separateNativeTask: true, committedNotesOnly: notesOnly, currentInputControl: true, ...(keyless ? { currentRefreshStarted: true } : {}) });
    expect(reads, "A notes-only consent refuses an audited audio read; an active consent admits its genuine authenticated recording").toHaveLength(notesOnly || keyless ? 0 : 1);
    expect(faults).toEqual([]);
  } finally {
    releaseInsight(); flags.IS_REACT_ACT_ENVIRONMENT = true;
    try { await act(async () => root.unmount()); await drain(); await drainPortalDraftWritesForTests(); }
    finally { restorers.reverse().forEach(restore => restore()); clearSession(); databases.forEach(database => database.close()); resetKvConnectionForTests(); setKvBackendForTests(null); vi.unstubAllGlobals(); container.remove(); dom.window.close(); account.noteKey.fill(0); keys.noteKey.fill(0); keys.authKey.fill(0); opened.noteKeyV2.fill(0); flags.IS_REACT_ACT_ENVIRONMENT = oldAct; server.closeAllConnections(); await finite(new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())), "owned native listener retirement"); }
  }
}, 60_000);
