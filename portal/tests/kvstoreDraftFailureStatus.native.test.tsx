import { act } from "react";
import { expect, it } from "vitest";
import { loadPortalDraft, usePortalDrafts } from "../src/noteDrafts";
import { setKvBackendForTests } from "../src/kvstore";
import { flush, render } from "./helpers/rtr";
import { drainPortalDraftWritesForTests, runTestControl } from "./helpers/testControl";

it.each(["exception", "opaque rejection"] as const)(
  "keeps the failed-save explanation beside the writing and recovers after an %s",
  async failure => {
    const owner = "draft-status-therapist";
    const patient = `draft-status-patient-${failure}`;
    const key = new Uint8Array(32).fill(7);
    const records = new Map<string, string>();
    let denied = false;
    runTestControl(setKvBackendForTests, {
      getItem: async id => records.get(id) ?? null,
      setItem: async (id, value) => {
        if (denied) {
          if (failure === "exception") throw new Error("host declined this draft write");
          throw { kind: "host-write-denied" };
        }
        records.set(id, value);
      },
      removeItem: async id => { records.delete(id); },
    });
    function DraftView() {
      const draft = usePortalDrafts(owner, patient, key, []);
      return <section>
        <p role="status">{draft.status}</p>
        <textarea aria-label="Clinical draft" value={draft.state.text.general ?? ""}
          onChange={event => draft.setState(previous => ({ ...previous, text: { ...previous.text, general: event.target.value } }))} />
        <button disabled={!draft.restored} onClick={() => draft.persist().catch(() => undefined)}>Save draft</button>
      </section>;
    }
    let root: Awaited<ReturnType<typeof render>> | undefined;
    try {
      root = await render(<DraftView />);
      await flush(12);
      const save = () => root!.root.findByType("button");
      if (save().props.disabled) throw new Error("SetupError: the empty-store draft did not finish restoring");
      denied = true;
      const writing = "Preserve this unsent clinical note while storage is unavailable.";
      await act(async () => {
        root!.root.findByType("textarea").props.onChange({ target: { value: writing } });
      });
      // The rendered event boundary handles the rejected operation. The first
      // oracle is the explanation displayed by the real exported draft hook.
      await act(async () => { await save().props.onClick(); });
      expect(root.root.findByProps({ role: "status" }).children.join(""))
        .toBe("Writing was not saved on this device — storage is full or unavailable. Keep it open and retry.");
      expect(root.root.findByType("textarea").props.value).toBe(writing);

      denied = false;
      await act(async () => { await save().props.onClick(); });
      expect(root.root.findByProps({ role: "status" }).children.join(""))
        .toBe("Draft saved encrypted on this device.");
      expect((await loadPortalDraft(owner, patient, [key]))?.text.general).toBe(writing);
    } finally {
      denied = false;
      try {
        if (root) await act(async () => { root!.unmount(); });
      } finally {
        try { await drainPortalDraftWritesForTests(); }
        finally { runTestControl(setKvBackendForTests, null); key.fill(0); }
      }
    }
  },
);
