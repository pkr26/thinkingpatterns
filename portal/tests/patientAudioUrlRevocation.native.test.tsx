/** Genuine Node Blob URL fetch outcomes after public playback retirement.
 * Node22/React HTML-media-event protocol only; no physical browser claim. */
import { createHash } from "node:crypto";
import { act } from "react";
import { expect, it, vi } from "vitest";
import * as portalCrypto from "../src/crypto";
import { openNativeChart } from "./helpers/prospectiveNativeChart";

// Preserve the actual platform fetch before the chart installs its owned HTTP
// origin transport. Blob URLs are then resolved by Node's native registry.
const nativeFetch = globalThis.fetch.bind(globalThis);

it.each(["stop", "ended", "error", "leave chart"] as const)("the actual native Blob URL stops resolving after current playback %s", async retirement => {
  const chart = await openNativeChart();
  try {
    await chart.evidence();
    await chart.press("play recording");
    await chart.audioVisible();
    const uri = String(chart.root().root.findByType("audio").props.src);
    const before = await nativeFetch(uri);
    expect(before.ok, "The current public audio URL resolves before retirement").toBe(true);
    const bytes = Buffer.from(await before.arrayBuffer());
    try {
      expect(createHash("sha256").update(bytes).digest("hex"), "The native URL yields the independently authenticated recording bytes").toBe(chart.account.audioDigest);
    } finally { bytes.fill(0); }

    if (retirement === "stop") await chart.press("stop recording");
    else if (retirement === "leave chart") {
      await chart.press("Back to patients");
      await chart.completed("public patient chart retired", () => chart.text().includes("Open patterns"));
    } else {
      // The currently mounted HTML audio element receives its declared public
      // ended/error event. No callback from an older player is retained.
      await act(async () => {
        const player = chart.root().root.findByType("audio");
        if (retirement === "ended") player.props.onEnded();
        else player.props.onError();
      });
    }
    await expect(nativeFetch(uri), "A retired recording URL cannot return its former plaintext through the actual native Blob registry").rejects.toThrow(TypeError);
  } finally {
    // Only cleanup uses the observer's captured native-returned URL strings.
    // The runtime oracle above never reads its active flags or cardinality.
    for (const uri of chart.urls.keys()) URL.revokeObjectURL(uri);
    await chart.retire();
  }
}, 30_000);


it("a real decrypt completion delivered after its current public Back reaction cannot leave an authentic native audio URL readable", async () => {
  const chart = await openNativeChart();
  const reactions: Promise<unknown>[] = [];
  let observedPlainDigest: string | undefined;
  try {
    await chart.evidence();
    const observer = vi.mocked(portalCrypto.decryptAudio);
    const forward = observer.getMockImplementation();
    if (!forward) throw new Error("Native chart's forwarding decrypt observer is unavailable");
    observer.mockImplementation(function (this: unknown, ...args) {
      const original = forward.apply(this, args);
      // Register before production receives this SAME exported Promise. The
      // original native operation and returned plaintext object are unchanged.
      const reaction = original.then(plain => {
        observedPlainDigest = createHash("sha256").update(plain).digest("hex");
        // The current enabled Back action synchronously retires its playback
        // generation. This is a declared JS component/Promise reaction protocol,
        // not a claim about physical browser event scheduling or forced commits.
        return chart.press("Back to all patterns");
      });
      reactions.push(reaction);
      return original;
    });
    await chart.press("play recording");
    await chart.completed("actual exported native audio decrypt admitted", () => reactions.length > 0);
    await chart.finishAudio();
    await Promise.all(reactions);
    expect(observedPlainDigest, "The reaction observes the genuine independently authenticated native decrypt result").toBe(chart.account.audioDigest);
    expect(chart.text()).toContain("See the evidence");
    const readableAudio: string[] = [];
    // Each string was actually returned by native URL.createObjectURL. Read
    // the native registry itself; its observer's active flags/counts are unused.
    for (const uri of chart.urls.keys()) {
      try {
        const response = await nativeFetch(uri);
        const bytes = Buffer.from(await response.arrayBuffer());
        try {
          if (createHash("sha256").update(bytes).digest("hex") === chart.account.audioDigest) readableAudio.push(uri);
        } finally { bytes.fill(0); }
      } catch (error) {
        if (!(error instanceof TypeError)) throw error;
      }
    }
    expect(readableAudio, "Completed public Back cannot leave authenticated recording plaintext readable through the actual native Blob registry").toEqual([]);
  } finally {
    await Promise.allSettled(reactions);
    for (const uri of chart.urls.keys()) URL.revokeObjectURL(uri);
    await chart.retire();
  }
}, 30_000);
