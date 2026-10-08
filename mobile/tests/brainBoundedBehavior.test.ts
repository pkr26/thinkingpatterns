import { readFileSync } from "node:fs";
import { expect, it } from "vitest";

const cases = JSON.parse(readFileSync(new URL("../../shared/brain_vectors.json", import.meta.url), "utf8")).sentiment.slice(0, 3) as Array<{text:string;score:number;pa:number;na:number}>;
it("bounded public sentiment consumers preserve independent Python scores and affect outputs", async () => {
  const { sentimentScore, sentimentComponents } = await import("../src/brain/sentiment");
  for (const { text, score, pa, na } of cases) {
    expect(sentimentScore(text)).toBeCloseTo(score, 12);
    const [positive, negative] = sentimentComponents(text);
    expect(positive).toBeCloseTo(pa, 6); expect(negative).toBeCloseTo(na, 6);
  }
});
