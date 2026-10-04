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
    expect(text).toContain("Journal entries and observations");
    expect(text).toContain("New accounts use a random data key");
    // The no-recovery honesty sits in the encryption section (zero-knowledge
    // cuts both ways) — the same sentence registration shows.
    expect(text).toContain("recovery kit");
    expect(text).toContain("we cannot recover your journal");
    // What the server sees
    expect(text).toContain("What the server sees");
    expect(text).toContain("when and how much you wrote — never what");
    // The analysis exception
    expect(text).toContain("Temporary server decryption");
    expect(text).toContain("kept in memory for up to 5 minutes");
    expect(text).toContain("never persisted by the server");
    // Optional transcript translation
    expect(text).toContain("Optional transcript translation");
    expect(text).toContain("Off by default");
    expect(text).toContain("transcript is sent as soon as it is recorded");
    expect(text).toContain("provider's retention policy applies");
    expect(text).toContain("journal entries are not sent to a third party for pattern analysis");
    // Deletion scope
    expect(text).toContain("Deleting your data");
    expect(text).toContain("live database");
    expect(text).toContain("backups and server logs expire on the operator's own schedule");
    expect(text).toContain("An export contains your scoped account content");
    expect(text).toContain("excludes security and operational records");
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
