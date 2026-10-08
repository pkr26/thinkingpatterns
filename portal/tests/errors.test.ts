import { expect, it } from "vitest";
import { ApiError } from "../src/api";
import { displayError } from "../src/errors";

it.each([
  { status: 409, code: "collection_changed", output: "rows changed while paging; retry the request" },
  { status: 409, code: "conflict", output: "note id already used for another patient" },
  { status: 409, code: "version_conflict", output: "a different note with this client_note_id already exists" },
  { status: 0, code: undefined, output: "server unreachable — check your connection" },
  { status: 499, code: undefined, output: "Default failure" },
  { status: 500, code: undefined, output: "server is busy — try again" },
  { status: 503, code: undefined, output: "server is busy — try again" },
  { status: 401, code: "unauthorized", output: "Default failure" },
  { status: 0, code: "collection_changed", output: "rows changed while paging; retry the request" },
])("uses stable client-owned copy for $status/$code", ({ status, code, output }) => {
  expect(displayError(new ApiError(status, "Server-controlled hostile detail", code), "Default failure")).toBe(output);
});

it("preserves local errors and safely falls back for non-errors", () => {
  expect(displayError(new Error("Retry local encrypted storage"), "Default failure")).toBe("Retry local encrypted storage");
  for (const unknown of [null, undefined, 42, "hostile detail", { message: "hostile detail" }]) {
    expect(displayError(unknown, "Default failure")).toBe("Default failure");
  }
});
