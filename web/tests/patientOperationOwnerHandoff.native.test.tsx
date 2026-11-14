import { act, useState } from "react";
import { afterEach, beforeEach, expect, it } from "vitest";
import { clearSession, sessionAbortSignal, sessionUserId, setSession } from "../src/api/client";
import { usePatientOperation, type PatientOperation } from "../src/patientOperation";
import { vault } from "../src/vault";
import { resetTestState } from "./helpers/api";
import { press, render } from "./helpers/rtr";

const OWNER_A = "patient-operation-owner-a";
const OWNER_B = "patient-operation-owner-b";

/** An ordinary public consumer of the exported hook's admission API. */
function Probe() {
  const begin = usePatientOperation();
  const [handle, setHandle] = useState<{ operation: PatientOperation } | null>(null);
  const [status, setStatus] = useState("Not checked");
  return (
    <>
      <button type="button" onClick={() => {
        const operation = begin();
        setHandle(operation ? { operation } : null);
        setStatus("Not checked");
      }}>Start operation</button>
      <button type="button" disabled={handle === null} onClick={() => {
        setStatus(handle ? String(handle.operation.current()) : "No operation");
      }}>Check operation</button>
      <p role="status" aria-label="Operation status">{status}</p>
    </>
  );
}

beforeEach(() => { resetTestState(); });
afterEach(() => { clearSession(); vault.lock(); });

it("renders an old operation as no longer current after a different vault owner adopts the same data-key object", async () => {
  setSession("patient-operation-public-probe-token", OWNER_A, "patient-probe");
  const dataKey = new Uint8Array(new ArrayBuffer(32)).fill(17);
  vault.unlock({ authKey: new Uint8Array(new ArrayBuffer(32)).fill(23), dataKey }, OWNER_A);
  const root = await render(<Probe />);
  const displayedStatus = () => root.root.findByProps({ role: "status", "aria-label": "Operation status" }).children.join("");
  try {
    await press(root, "Start operation");
    await press(root, "Check operation");
    expect(displayedStatus()).toBe("true");

    const sameDataKey = vault.get().dataKey;
    expect(sameDataKey).toBe(dataKey);
    vault.unlock({ authKey: new Uint8Array(new ArrayBuffer(32)).fill(29), dataKey: sameDataKey }, OWNER_B);
    expect(vault.get().dataKey).toBe(sameDataKey);
    expect(vault.ownerUserId()).toBe(OWNER_B);
    expect(sessionUserId()).toBe(OWNER_A);

    await press(root, "Check operation");
    expect(displayedStatus()).toBe("false");
  } finally {
    clearSession();
    vault.lock();
    await act(async () => { root.unmount(); });
  }
});

// A listener can create a nested session while the old session is retiring.
it("rejects an operation captured by a reentrant same-owner session superseded during logout", async () => {
  setSession("outer-old", OWNER_A, "patient-probe");
  const dataKey = new Uint8Array(new ArrayBuffer(32)).fill(17);
  vault.unlock({ authKey: new Uint8Array(new ArrayBuffer(32)).fill(23), dataKey }, OWNER_A);
  let begin!: ReturnType<typeof usePatientOperation>;
  function SessionProbe() { begin = usePatientOperation(); return <p>Session probe</p>; }
  const root = await render(<SessionProbe />);
  const retiring = sessionAbortSignal();
  expect(retiring).not.toBeNull();
  const observed: { operation: PatientOperation | null; signal: AbortSignal | null } = { operation: null, signal: null };
  try {
    retiring!.addEventListener("abort", () => {
      setSession("nested", OWNER_A, "patient-probe");
      observed.signal = sessionAbortSignal();
      observed.operation = begin();
    }, { once: true });
    setSession("outer-successor", OWNER_A, "patient-probe");
    expect(observed.operation).not.toBeNull();
    expect(observed.signal).not.toBeNull();
    expect(observed.signal!.aborted).toBe(false);
    expect(sessionAbortSignal()).not.toBe(observed.signal);
    expect(sessionUserId()).toBe(OWNER_A);
    expect(observed.operation!.viewCurrent()).toBe(false);
    expect(observed.operation!.current()).toBe(false);
  } finally {
    clearSession();
    vault.lock();
    await act(async () => { root.unmount(); });
  }
});
