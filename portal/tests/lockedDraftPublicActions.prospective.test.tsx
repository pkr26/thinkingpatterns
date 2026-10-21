import { expect, it } from "vitest";
import { openNativeChart, SAVED_DRAFT, SAVED_NOTE } from "./helpers/prospectiveNativeChart";

it("keeps public template and copy-forward locked until encrypted draft retry restores saved writing", async () => {
  const chart = await openNativeChart({ failFirstDraftRead: true });
  try {
    expect(chart.composer().props.disabled).toBe(true);
    expect(chart.button("Session focus").props.disabled).toBe(true);
    expect(chart.button("Copy forward last note").props.disabled).toBe(true);
    await chart.press("Retry restoring encrypted draft");
    await chart.completed("authenticated draft restored", () => chart.composer().props.value === SAVED_DRAFT);
    expect(chart.composer().props.value).toBe(SAVED_DRAFT);
    expect(chart.composer().props.disabled).toBe(false);
    expect(chart.button("Session focus").props.disabled).toBe(false);
    expect(chart.button("Copy forward last note").props.disabled).toBe(false);
    chart.clean();
  } finally { await chart.retire(); }
}, 60000);

it("keeps restored template and copy-forward actions available through their public buttons", async () => {
  const chart = await openNativeChart();
  try {
    await chart.press("Session focus");
    expect(chart.composer().props.value).toContain(SAVED_DRAFT);
    expect(chart.composer().props.value).toContain("Session focus:");
    await chart.press("Copy forward last note");
    expect(chart.composer().props.value).toBe(SAVED_NOTE);
    chart.clean();
  } finally { await chart.retire(); }
}, 60000);
