import { act } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { MeasuresView } from "../src/views/Measures";
import { kv, setKvBackendForTests } from "../src/kvstore";
import { setSession } from "../src/api/client";
import { __setLocaleForTests, t } from "../src/strings";
import { vault } from "../src/vault";
import { installSession, jsonResponse, memoryKvBackend, resetTestState, stubFetch } from "./helpers/api";
import { press, render, settle, textOfNode, waitForResult } from "./helpers/rtr";

const OWNER = "measures366-current-owner";
const key = () => new Uint8Array(new ArrayBuffer(32)).fill(29);

beforeEach(() => {
  resetTestState();
  __setLocaleForTests("en");
  setKvBackendForTests(memoryKvBackend());
  installSession(OWNER);
  vault.unlock({ authKey: key(), dataKey: key() }, OWNER);
});

afterEach(() => {
  vi.unstubAllGlobals();
  setKvBackendForTests(null);
  __setLocaleForTests("en");
});

it("a retired save cannot re-enable the in-flight questionnaire control", async () => {
  let posts = 0;
  stubFetch((url, init) => {
    if (new URL(url).pathname.endsWith("/measures")) {
      if (init.method === "POST") {
        posts += 1;
        return jsonResponse({ id: "unexpected" }, { status: 201 });
      }
      return jsonResponse([], { headers: { "X-Measures-Revision": "8" } });
    }
    return jsonResponse({}, { status: 404 });
  });

  let release!: () => void;
  let captureReached = false;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const capture = kv.captureWritePermit.bind(kv);
  const owned: Promise<Awaited<ReturnType<typeof capture>>>[] = [];
  const captureSpy = vi.spyOn(kv, "captureWritePermit").mockImplementation((...args) => {
    const pending = capture(...args).then(async permit => {
      captureReached = true;
      await gate;
      return permit;
    });
    owned.push(pending);
    return pending;
  });

  let root: Awaited<ReturnType<typeof render>> | undefined;
  try {
    root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(15, 3);
    await press(root, "PHQ-2");
    const answer = async (index: number, label: string): Promise<void> => {
      const button = root!.root.findAllByType("button").filter(node => textOfNode(node) === label)[index];
      if (!button || typeof button.props.onClick !== "function") throw new Error("SetupError: answer control absent");
      await act(async () => { button.props.onClick(); });
    };
    await answer(0, "Several days");
    await answer(1, "More than half the days");
    await press(root, "Save measure");
    await waitForResult(() => captureReached, "native write-permit capture", 10_000);
    const saving = () => root!.root.findAllByType("button").find(node => textOfNode(node) === t("entry.saving"));
    expect(saving()?.props.disabled, "The old in-flight form is visibly busy before session replacement").toBe(true);

    // The component stays mounted long enough for the old operation to
    // resolve. Its original session signal has been aborted by setSession.
    setSession("replacement-token-366", OWNER, "replacement");
    await act(async () => { release(); await Promise.all(owned); });
    await settle(15, 2);
    expect(posts, "The retired operation must not dispatch a POST").toBe(0);
    expect(saving()?.props.disabled, "A retired operation must not re-enable this old in-flight control").toBe(true);
  } finally {
    release();
    await act(async () => { await Promise.all(owned); if (root) root.unmount(); });
    captureSpy.mockRestore();
  }
});
