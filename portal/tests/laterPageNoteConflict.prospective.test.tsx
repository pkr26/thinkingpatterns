import { expect, it } from "vitest";
import { openNativeChart, MINE, WINNING_NOTE, OWNER, PATIENT } from "./helpers/prospectiveNativeChart";

it("refreshes a later-page authenticated winning note before retrying the preserved public edit", async () => {
  const chart = await openNativeChart({ conflict: true, laterPage: true });
  try {
    await chart.editTarget(); await chart.press("Save edit");
    await chart.completed("public conflict reply settles", () => chart.text().includes("This note changed on another device") && chart.button("Save edit").props.disabled === false);
    expect(chart.text()).toContain(`Current saved text: ${WINNING_NOTE}`);
    expect(chart.root().root.findByProps({ placeholder: "Editing note…" }).props.value).toBe(MINE);
    await chart.press("Save edit");
    await chart.completed("public conflict retry succeeds", () => !chart.root().root.findAllByType("textarea").some(node => node.props.placeholder === "Editing note…"));
    expect(chart.text()).toContain(MINE);
    expect(chart.patchBodies.map(row => row.baseVersion)).toEqual([4, 5]);
    expect(chart.patchBodies[1]?.plaintext).toBe(MINE);
    expect(chart.patchBodies[1]?.aad).toEqual(["note", OWNER, PATIENT, chart.account.target.client_note_id]);
    expect(chart.requests.some(row => row.path.endsWith(`/patients/${PATIENT}/notes`) && row.offset === "100" && row.revision === "8")).toBe(true);
    chart.clean();
  } finally { await chart.retire(); }
}, 60000);

it("preserves the first-page native conflict control and independently authenticated retry payload", async () => {
  const chart = await openNativeChart({ conflict: true });
  try {
    await chart.editTarget(); await chart.press("Save edit");
    await chart.completed("first-page public conflict settles", () => chart.text().includes("This note changed on another device") && chart.button("Save edit").props.disabled === false);
    expect(chart.text()).toContain(`Current saved text: ${WINNING_NOTE}`);
    expect(chart.root().root.findByProps({ placeholder: "Editing note…" }).props.value).toBe(MINE);
    await chart.press("Save edit");
    await chart.completed("first-page public retry succeeds", () => !chart.root().root.findAllByType("textarea").some(node => node.props.placeholder === "Editing note…"));
    expect(chart.patchBodies.map(row => row.baseVersion)).toEqual([4, 5]);
    expect(chart.patchBodies[1]?.plaintext).toBe(MINE);
    expect(chart.text()).toContain(MINE);
    chart.clean();
  } finally { await chart.retire(); }
}, 60000);
