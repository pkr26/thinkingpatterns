import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { act } from "react";
import { expect, it, vi } from "vitest";
import { loadPortalDraft, usePortalDrafts, type DraftState } from "../src/noteDrafts";
import { setKvBackendForTests } from "../src/kvstore";
import { render } from "./helpers/rtr";
import { drainPortalDraftWritesForTests, runTestControl } from "./helpers/testControl";

type Context = { owner: string; patient: string };
const previous: Context = { owner: "cleanup-clinician", patient: "cleanup-patient-a" };
const replacement: Context = { owner: previous.owner, patient: "cleanup-patient-b" };
const storedState: DraftState = {
  text: { general: "Previously acknowledged patient A writing" },
  editing: { id: "previous-edit", text: "Previous edit text" },
  pending: { general: { client_note_id: "previous-request", blob: "previous-opaque-request", text: "Previous pending writing", pattern_pid: null } },
};
const editedState: DraftState = {
  text: { general: "Patient A writing committed when this view leaves its context", pattern: "Additional independent pattern writing" },
  editing: { id: "edited-note", text: "Edited note text" },
  pending: { pattern: { client_note_id: "edited-request", blob: "edited-opaque-request", text: "Edited pending writing", pattern_pid: "edited-pattern" } },
};
const slot = ({ owner, patient }: Context): string => `portal.draft.${owner}.${patient}`;
const aad = ({ owner, patient }: Context): Buffer => Buffer.from(JSON.stringify(["portal-draft", owner, patient]));

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

it("commits the old patient's visible writing before a same-view context handoff can be read back", async () => {
  // Native AES256 accepts these32 bytes. Legitimate hook-owned cleanup fill(0)
  // preserves this key's numeric value without touching any private hook ref.
  const borrowedKey = new Uint8Array(32);
  const initialRow = sealed(borrowedKey, previous, storedState);
  expect(opened(borrowedKey, previous, initialRow)).toEqual({ v: 1, state: storedState });
  // Replacement B has no saved row, so its automatic load requires no native
  // decrypt. Its readiness is never an observation or completion oracle here.
  const rows = new Map([[slot(previous), initialRow]]);
  runTestControl(setKvBackendForTests, {
    getItem: async id => rows.get(id) ?? null,
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
  const published = (label: string): string => root!.root.findByProps({ "aria-label": label }).children.join("");
  try {
    root = await render(<Harness context={previous} />);
    // Setup/readiness only0K. No public edit has run; restoring via rawSetState
    // leaves revision0 and therefore schedules no initial debounce timer.
    await vi.waitFor(() => expect(published("published draft state")).toBe(JSON.stringify(storedState)));
    expect(published("published draft readiness")).toBe("ready");

    // Freeze BEFORE the first user edit. Never advance or run these timers;
    // native Promise/crypto work, setImmediate and Date retain their providers.
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    await act(async () => { publicDraft.setState(editedState); });
    expect(published("published draft state")).toBe(JSON.stringify(editedState));
    await act(async () => { root!.update(<Harness context={replacement} />); });

    // Exact public read completion awaits A's owning cleanup write. This
    // fulfilled whole-value comparison is before final unmount, which could
    // otherwise repair an omitted context cleanup. No B wait or timer oracle.
    await act(async () => {
      await expect(loadPortalDraft(previous.owner, previous.patient, [borrowedKey])).resolves.toEqual(editedState);
    });
  } finally {
    try {
      // Keep the clock frozen until unmount has cleared any debounce and every
      // owning native cleanup write has drained. Preserve the original backend.
      if (root) await act(async () => { root!.unmount(); });
    } finally {
      try { await drainPortalDraftWritesForTests(); }
      finally {
        try { runTestControl(setKvBackendForTests, null); }
        finally { vi.useRealTimers(); }
      }
    }
  }
});
