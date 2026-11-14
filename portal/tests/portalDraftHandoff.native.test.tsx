import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { act } from "react";
import { expect, it, vi } from "vitest";
import { usePortalDrafts, type DraftState } from "../src/noteDrafts";
import { setKvBackendForTests } from "../src/kvstore";
import { render } from "./helpers/rtr";
import { drainPortalDraftWritesForTests, runTestControl } from "./helpers/testControl";

type Context = { owner: string; patient: string };
const oldContext: Context = { owner: "handoff-clinician-a", patient: "handoff-patient-a" };
const oldState: DraftState = {
  text: { general: "Earlier patient's independent saved writing" },
  editing: { id: "earlier-edit", text: "Earlier edit text" },
  pending: { general: { client_note_id: "earlier-request", blob: "earlier-opaque-record", text: "Earlier pending writing", pattern_pid: null } },
};
const newState: DraftState = {
  text: { general: "Replacement context's independent saved writing", pattern: "Replacement pattern writing" },
  editing: { id: "replacement-edit", text: "Replacement edit text" },
  pending: { pattern: { client_note_id: "replacement-request", blob: "replacement-opaque-record", text: "Replacement pending writing", pattern_pid: "replacement-pattern" } },
};
const slot = ({ owner, patient }: Context): string => `portal.draft.${owner}.${patient}`;
const aad = ({ owner, patient }: Context): Buffer => Buffer.from(JSON.stringify(["portal-draft", owner, patient]));

// Independently authored native AES-GCM envelopes; no production crypto helper
// computes expected plaintext, AAD, or wire layout.
function sealed(key: Uint8Array, context: Context, state: DraftState): string {
  const nonce = randomBytes(12);
  const plain = Buffer.from(JSON.stringify({ v: 1, state }));
  try {
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(aad(context));
    return Buffer.concat([nonce, cipher.update(plain), cipher.final(), cipher.getAuthTag()]).toString("base64");
  } finally {
    plain.fill(0);
  }
}

function opened(key: Uint8Array, context: Context, encoded: string): unknown {
  const wire = Buffer.from(encoded, "base64");
  const decipher = createDecipheriv("aes-256-gcm", key, wire.subarray(0, 12));
  decipher.setAAD(aad(context));
  decipher.setAuthTag(wire.subarray(wire.length - 16));
  const plain = Buffer.concat([decipher.update(wire.subarray(12, -16)), decipher.final()]);
  try {
    return JSON.parse(plain.toString("utf8"));
  } finally {
    plain.fill(0);
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(accept => { resolve = accept; });
  return { promise, resolve };
}

it.each([
  { label: "patient", next: { owner: oldContext.owner, patient: "handoff-patient-b" } },
  { label: "owner", next: { owner: "handoff-clinician-b", patient: oldContext.patient } },
])("keeps the replacement $label draft authoritative when the same view's earlier restore finishes", async ({ next }) => {
  // This is a valid native AES256 key, not a missing/empty key. The hook owns a
  // private copy and legitimately zeroizes it on context cleanup; all-zero
  // numeric material remains the same valid AES key across that cleanup.
  const borrowedKey = new Uint8Array(32);
  const oldRow = sealed(borrowedKey, oldContext, oldState);
  const newRow = sealed(borrowedKey, next, newState);
  expect(opened(borrowedKey, oldContext, oldRow)).toEqual({ v: 1, state: oldState });
  expect(opened(borrowedKey, next, newRow)).toEqual({ v: 1, state: newState });
  const rows = new Map([[slot(oldContext), oldRow], [slot(next), newRow]]);
  const oldReadEntered = deferred<void>();
  const oldReadResponse = deferred<string | null>();
  let holdOldRead = false;
  runTestControl(setKvBackendForTests, {
    getItem: id => {
      if (holdOldRead && id === slot(oldContext)) {
        oldReadEntered.resolve();
        return oldReadResponse.promise;
      }
      return Promise.resolve(rows.get(id) ?? null);
    },
    setItem: async (id, value) => { rows.set(id, value); },
    removeItem: async id => { rows.delete(id); },
  });

  let publicDraft!: ReturnType<typeof usePortalDrafts>;
  function Harness({ context }: { context: Context }) {
    publicDraft = usePortalDrafts(context.owner, context.patient, borrowedKey, []);
    return <>
      <output aria-label="published draft state">{JSON.stringify(publicDraft.state)}</output>
      <output aria-label="published draft readiness">{publicDraft.restored ? "ready" : "loading"}</output>
    </>;
  }
  let root: Awaited<ReturnType<typeof render>> | undefined;
  let oldRestore: Promise<void> | undefined;
  const published = (label: string): string => root!.root.findByProps({ "aria-label": label }).children.join("");
  const expectPublished = async (expected: DraftState): Promise<void> => {
    // Readiness precondition only: a miss here gets no mutation credit. In
    // particular this does not qualify an omitted automatic restore (212).
    // Only the rendered value is retried, with no elapsed-time assertion.
    await vi.waitFor(() => expect(published("published draft state")).toBe(JSON.stringify(expected)));
    expect(published("published draft readiness")).toBe("ready");
  };
  try {
    root = await render(<Harness context={oldContext} />);
    await expectPublished(oldState);
    holdOldRead = true;
    await act(async () => {
      oldRestore = publicDraft.restore();
      void oldRestore.catch(() => undefined);
      // Fixture admission only: the original exported restore Promise remains
      // owned, unmodified, and pending until its original read is released.
      await oldReadEntered.promise;
    });
    await act(async () => { root!.update(<Harness context={next} />); });
    await expectPublished(newState);

    await act(async () => {
      oldReadResponse.resolve(oldRow);
      await oldRestore;
    });
    // The finite oracle for generation-collision candidates 168/207 follows
    // exact completion of the old exported operation. It is not the earlier
    // readiness retry. Earlier context data must not replace the new view.
    expect(published("published draft state")).toBe(JSON.stringify(newState));
    expect(published("published draft readiness")).toBe("ready");
  } finally {
    oldReadResponse.resolve(oldRow);
    if (oldRestore) await act(async () => { await Promise.allSettled([oldRestore!]); });
    try {
      if (root) await act(async () => { root!.unmount(); });
    } finally {
      try { await drainPortalDraftWritesForTests(); }
      finally { runTestControl(setKvBackendForTests, null); }
    }
  }
});


it("reads and publishes the replacement patient's saved draft after a context change", async () => {
  const borrowedKey = new Uint8Array(32);
  const next = { owner: oldContext.owner, patient: "handoff-patient-b" };
  const rows = new Map([[slot(oldContext), sealed(borrowedKey, oldContext, oldState)], [slot(next), sealed(borrowedKey, next, newState)]]);
  const reads: string[] = [];
  runTestControl(setKvBackendForTests, {
    getItem: async id => { reads.push(id); return rows.get(id) ?? null; },
    setItem: async (id, value) => { rows.set(id, value); },
    removeItem: async id => { rows.delete(id); },
  });
  function Harness({ context }: { context: Context }) {
    const draft = usePortalDrafts(context.owner, context.patient, borrowedKey, []);
    return <output aria-label="published draft state">{JSON.stringify(draft.state)}</output>;
  }
  const root = await render(<Harness context={oldContext} />);
  const state = () => root.root.findByProps({ "aria-label": "published draft state" }).children.join("");
  try {
    await vi.waitFor(() => expect(state()).toBe(JSON.stringify(oldState)));
    reads.length = 0;
    await act(async () => { root.update(<Harness context={next} />); });
    expect(reads).toContain(slot(next));
    await vi.waitFor(() => expect(state()).toBe(JSON.stringify(newState)));
  } finally {
    try { await act(async () => root.unmount()); }
    finally { try { await drainPortalDraftWritesForTests(); } finally { runTestControl(setKvBackendForTests, null); } }
  }
});
