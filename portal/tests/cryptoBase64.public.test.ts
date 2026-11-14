import { expect, it } from "vitest";
import { fromBase64 } from "../src/crypto";

it("decodes a nonempty base64 value", () => {
  expect(Array.from(fromBase64("AQID"))).toEqual([1, 2, 3]);
});
