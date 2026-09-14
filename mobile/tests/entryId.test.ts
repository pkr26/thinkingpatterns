/**
 * newClientEntryId: real-entropy ids inside the backend's contract band.
 * A collision here is silent data loss (the server dedupes on this id), so
 * uniqueness is the pinned property.
 */
import { describe, expect, it } from "vitest";
import { newClientEntryId } from "../src/entryId";

describe("newClientEntryId", () => {
  it("stays inside the [A-Za-z0-9_-]{1,64} contract band", () => {
    for (let i = 0; i < 200; i++) {
      const id = newClientEntryId("2026-09-07");
      expect(id).toMatch(/^[A-Za-z0-9_-]{1,64}$/);
      expect(id.startsWith("e-2026-09-07-")).toBe(true);
    }
  });

  it("never collides across a large batch (the same-millisecond case)", () => {
    const ids = new Set<string>();
    for (let i = 0; i < 10_000; i++) ids.add(newClientEntryId("2026-09-07"));
    expect(ids.size).toBe(10_000);
  });

  it("keeps the entry date in the id prefix", () => {
    expect(newClientEntryId("2026-01-31")).toMatch(/^e-2026-01-31-[A-Za-z0-9_-]{12}$/);
  });
});
