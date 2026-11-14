import { createDecipheriv } from "node:crypto";
import { expect, it } from "vitest";
import { loadPortalDraft, savePortalDraft, type DraftState } from "../src/noteDrafts";
import { setKvBackendForTests } from "../src/kvstore";
import { runTestControl } from "./helpers/testControl";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(accept => { resolve = accept; });
  return { promise, resolve };
}

// Independent native authentication identifies the admitted real B write by
// its plaintext, rather than a provider write count or private queue state.
function opened(key: Uint8Array, owner: string, patient: string, encoded: string): unknown {
  const wire = Buffer.from(encoded, "base64");
  const decipher = createDecipheriv("aes-256-gcm", key, wire.subarray(0, 12));
  decipher.setAAD(Buffer.from(JSON.stringify(["portal-draft", owner, patient])));
  decipher.setAuthTag(wire.subarray(wire.length - 16));
  const plain = Buffer.concat([decipher.update(wire.subarray(12, -16)), decipher.final()]);
  try {
    return JSON.parse(plain.toString("utf8"));
  } finally {
    plain.fill(0);
  }
}

it("reads the latest admitted writing after an earlier queued write finishes", async () => {
  const owner = "queued-read-clinician";
  const patient = "queued-read-patient";
  const key = new Uint8Array(32).fill(67);
  const slot = `portal.draft.${owner}.${patient}`;
  const firstState: DraftState = {
    text: { general: "Earlier acknowledged writing" },
    editing: null,
    pending: {},
  };
  const secondState: DraftState = {
    text: { general: "Latest admitted writing whose durable commit is pending" },
    editing: { id: "latest-edit", text: "Latest independent edit" },
    pending: { general: { client_note_id: "latest-request", blob: "latest-opaque-request", text: "Latest pending writing", pattern_pid: null } },
  };
  const rows = new Map<string, string>();
  const secondWriteEntered = deferred<void>();
  const releaseSecondWrite = deferred<void>();
  runTestControl(setKvBackendForTests, {
    // Each actual get owns an immutable string snapshot taken at admission.
    // A later write cannot alter the value already returned by this backend.
    getItem: async id => rows.get(id) ?? null,
    setItem: async (id, value) => {
      if (id === slot) {
        const row = opened(key, owner, patient, value) as { v?: unknown; state?: DraftState };
        if (row.v === 1 && row.state?.text.general === secondState.text.general) {
          secondWriteEntered.resolve();
          // Hold the genuine write BEFORE the durable value changes; its
          // owning exported save Promise remains pending and unmodified.
          await releaseSecondWrite.promise;
        }
      }
      rows.set(id, value);
    },
    removeItem: async id => { rows.delete(id); },
  });

  let firstSave: Promise<void> | undefined;
  let secondSave: Promise<void> | undefined;
  let pendingRead: ReturnType<typeof loadPortalDraft> | undefined;
  let independentRead: ReturnType<typeof loadPortalDraft> | undefined;
  try {
    // Both public writes register synchronously before the first native
    // encryption/commit can settle. No private pending-map reference is read.
    firstSave = savePortalDraft(owner, patient, key, firstState);
    secondSave = savePortalDraft(owner, patient, key, secondState);
    void firstSave.catch(() => undefined);
    void secondSave.catch(() => undefined);
    await firstSave;
    // A refused or unexpectedly completed owning B save is setup failure,
    // so it must reach finally rather than strand the admission ACK.
    await Promise.race([
      secondWriteEntered.promise,
      secondSave.then(
        () => { throw new Error("SetupError: queued B save completed before authenticated write admission"); },
        cause => { throw new Error("SetupError: queued B save refused before authenticated write admission", { cause }); },
      ),
    ]);

    pendingRead = loadPortalDraft(owner, patient, [key]);
    void pendingRead.catch(() => undefined);
    // This separate public empty-slot read completes through the same native
    // Promise/KV path. It is a sequencing precondition only, with no timing,
    // turn-count, pending-status or provider-call-count oracle. Under native
    // FIFO Promise jobs, a same-slot read that skipped its newer write tail
    // has already acquired its old immutable row before this read completes.
    // A correct same-slot read remains waiting for the owning B tail.
    independentRead = loadPortalDraft(owner, "independent-empty-patient", [key]);
    await expect(independentRead).resolves.toBeNull();

    releaseSecondWrite.resolve();
    await secondSave;
    // FIRST proposed finite observation: the completed value of the SAME
    // exported read issued while the newer admitted commit was outstanding.
    // Re-reading after the commit would hide the wrong-tail cleanup bug.
    await expect(pendingRead).resolves.toEqual(secondState);
  } finally {
    releaseSecondWrite.resolve();
    // Own and settle every exported operation directly. This actor never
    // invokes the test-only drain loop or inspects private map membership.
    await Promise.allSettled([firstSave, secondSave, pendingRead, independentRead]
      .filter((p): p is Promise<void> | ReturnType<typeof loadPortalDraft> => p !== undefined));
    try { runTestControl(setKvBackendForTests, null); }
    finally { key.fill(0); }
  }
});
