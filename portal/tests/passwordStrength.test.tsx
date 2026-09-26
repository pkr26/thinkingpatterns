/** Password-strength meter (2026-09-26 audit, UX parity): the portal's
 *  register form now carries the same 4-segment meter + Weak/Fair/Good/
 *  Strong label the patient web app's register form got. The ladder
 *  mirrors the policy text the form already shows (12+ characters, or
 *  16+ as a passphrase; character classes at 12–15) and stays
 *  display-only — passwordPolicyError remains the enforced contract
 *  (pinned in views.test.tsx and the mutation pins). */
import { describe, expect, it, vi } from "vitest";
import React from "react";
import { PasswordStrengthMeter } from "../src/ui";
import { passwordPolicyError, passwordStrength } from "../src/views/LoginView";
import { render, textOf, press, typeInto } from "./helpers/rtr";
import { LoginView } from "../src/views/LoginView";

describe("passwordStrength ladder (mirrors the web app's strengthOf)", () => {
  it("empty shows nothing (0)", () => {
    expect(passwordStrength("")).toBe(0);
  });

  it("under the 12-character floor is Weak (1)", () => {
    expect(passwordStrength("a")).toBe(1);
    expect(passwordStrength("Str0ng!x")).toBe(1);
    expect(passwordStrength("a".repeat(11))).toBe(1);
  });

  it("12+ characters that still fail the policy are Fair (2)", () => {
    // Two character classes at 12–15 characters: the policy demands the
    // 16-character passphrase lane instead.
    expect(passwordStrength("alllowercase12")).toBe(2);
    expect(passwordPolicyError("alllowercase12")).not.toBe("");
    expect(passwordStrength("AAAAAAAAAA01")).toBe(2);
    expect(passwordStrength("aaaaaaaaaa!!")).toBe(2);
  });

  it("policy-passing 12–15 character passwords are Good (3)", () => {
    expect(passwordStrength("Strong!pass123")).toBe(3);
    expect(passwordPolicyError("Strong!pass123")).toBe("");
  });

  it("16+ characters are Strong (4) — including a plain long passphrase", () => {
    expect(passwordStrength("four correct horse battery staple")).toBe(4);
    expect(passwordStrength("Strong!pass123456")).toBe(4);
  });

  it("the ladder is monotonic in the policy it mirrors", () => {
    expect(passwordStrength("")).toBeLessThan(passwordStrength("short"));
    expect(passwordStrength("short")).toBeLessThan(passwordStrength("alllowercase12"));
    expect(passwordStrength("alllowercase12")).toBeLessThan(passwordStrength("Strong!pass123"));
    expect(passwordStrength("Strong!pass123")).toBeLessThan(passwordStrength("four correct horse battery staple"));
  });
});

describe("PasswordStrengthMeter (kit component)", () => {
  const meterAt = async (strength: 0 | 1 | 2 | 3 | 4) => {
    const root = await render(<PasswordStrengthMeter strength={strength} />);
    return root.root.findAll((n) => String(n.props.className ?? "").startsWith("pw-meter"));
  };

  it("renders nothing at strength 0", async () => {
    expect((await meterAt(0)).length).toBe(0);
  });

  it.each([
    [1, "Weak", 1],
    [2, "Fair", 2],
    [3, "Good", 3],
    [4, "Strong", 4],
  ] as const)("strength %i fills %i segments and labels %s", async (strength, label, filled) => {
    const root = await render(<PasswordStrengthMeter strength={strength} />);
    const bars = root.root.findAll((n) => String(n.props.className ?? "").includes("pw-meter__bar"));
    expect(bars.length).toBe(4); // exactly four segments
    expect(bars.filter((n) => String(n.props.className).includes(`pw-meter__bar--${strength}`))).toHaveLength(filled);
    expect(textOf(root)).toContain(label);
    const live = root.root.findAllByType("div").find((n) => n.props.className === "pw-meter")!;
    expect(live.props.role).toBe("status");
    expect(live.props["aria-label"]).toBe(`Password strength: ${label}`);
  });
});

describe("LoginView register form carries the meter under the Password field", () => {
  it("the meter appears only in register mode, tracking the typed password", async () => {
    // The enrollment-policy check fires on mode switch; keep it offline.
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("offline"))));
    try {
      const root = await render(<LoginView onReady={vi.fn()} />);
      const loginMeter = root.root.findAll((n) => n.props.className === "pw-meter");
      expect(loginMeter.length).toBe(0); // sign-in mode: no meter

      await press(root, "Create a therapist account instead");
      expect(root.root.findAll((n) => n.props.className === "pw-meter").length).toBe(0); // empty password: still nothing

      await typeInto(root, "Password", "alllowercase12");
      const fair = root.root.findAllByType("div").find((n) => n.props.className === "pw-meter")!;
      expect(fair.props["aria-label"]).toBe("Password strength: Fair");

      await typeInto(root, "Password", "four correct horse battery staple");
      const strong = root.root.findAllByType("div").find((n) => n.props.className === "pw-meter")!;
      expect(strong.props["aria-label"]).toBe("Password strength: Strong");
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
