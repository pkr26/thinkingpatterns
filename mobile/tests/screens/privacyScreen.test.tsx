/**
 * PrivacyScreen: the in-app privacy policy — static and offline like the
 * crisis screen. Renders every promised section in plain language; the two
 * entry points (Onboarding's encryption panel, Settings → About) are
 * covered in those screens' tests, and the route itself in navigation tests.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";

const { PrivacyScreen } = await import("../../src/screens/PrivacyScreen");
const { render, flush, textOf, pressLabel } = await import("../helpers/rtr");

const nav = { navigate: vi.fn() };

beforeEach(() => {
  nav.navigate.mockClear();
});

describe("PrivacyScreen", () => {
  it("renders every promised section in plain language", async () => {
    const root = await render(<PrivacyScreen navigation={nav} />);
    await flush();
    const text = textOf(root);
    expect(text).toContain("Privacy, in plain language");
    // What's encrypted
    expect(text).toContain("What is encrypted");
    expect(text).toContain("Everything you write");
    expect(text).toContain("The server stores only ciphertext");
    // The no-recovery honesty sits in the encryption section (zero-knowledge
    // cuts both ways) — the same sentence registration shows.
    expect(text).toContain("There is no password reset");
    expect(text).toContain("no one — including us — can recover your journal");
    // What the server sees
    expect(text).toContain("What the server sees");
    expect(text).toContain("when and how much you wrote — never what");
    // The analysis exception
    expect(text).toContain("The one exception: pattern analysis");
    expect(text).toContain("held in memory for up to 5 minutes");
    expect(text).toContain("never sent for any other reason");
    // Optional AI analysis
    expect(text).toContain("Optional AI analysis");
    expect(text).toContain("Off by default");
    expect(text).toContain("provider's data-retention policy applies");
    // Deletion scope
    expect(text).toContain("Deleting your data");
    expect(text).toContain("live database");
    expect(text).toContain("backups and server logs expire on the operator's own schedule");
    expect(text).toContain("An exported bundle includes everything");
  });

  it("works fully offline — the policy lives in the app binary", async () => {
    // No api client, no vault, no storage is imported by this screen at
    // all; rendering with no mocks in place must just work.
    const root = await render(<PrivacyScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("needs no connection and leaves no trace");
  });

  it("crisis help stays one tap away", async () => {
    const root = await render(<PrivacyScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Need help now? Crisis resources");
    expect(nav.navigate).toHaveBeenCalledWith("Crisis");
  });
});
