/**
 * UI kit — calm, clinical, no dependencies (redesign 2026-09-26).
 * Components render through the token-driven classes in public/portal.css;
 * the `theme` object stays exported (refreshed values + the previously
 * MISSING `warn` token) for the views' SVG stroke/fill ATTRIBUTES (e.g.
 * the mood sparkline), which CSP style-src does not govern. Every former
 * inline style object moved to portal.css classes in the 2026-09-26 CSP
 * hardening, so nothing here or in the views may set a style attribute.
 *
 * Contracts kept: Buttons are real <button>s whose handler is absent when
 * disabled; cards are sections with h2 titles; Field wraps its input in
 * the label; Note preserves line breaks; ErrorBanner announces with
 * role=alert.
 */
import type { ReactNode } from "react";

/** Mirrors the CSS custom properties in public/portal.css (guarded by
 *  tests/designTokens.test.ts). 2026-09-26 audit corrections:
 *   - accent/accentBright follow the AA-corrected button palette
 *     (--primary/--primary-strong — white labels now clear 4.5:1);
 *   - warn/ok/danger mirror the color those tones actually RENDER with
 *     (--warn-strong/--ok-strong/--danger-strong — .note--warn and
 *     friends color their text with the *-strong variants, so the old
 *     base-token mirrors were tone drift). */
export const theme = {
  bg: "#0d1219",
  card: "#151b28",
  cardDeep: "#101622",
  text: "#e8edf6",
  body: "#c6cfdd",
  muted: "#8a95a3",
  accent: "#2f6fe0",
  accentBright: "#7db0ff",
  danger: "#f0a89e",
  ok: "#7cc7a2",
  warn: "#e5b87e",
  border: "#232b3b",
  radius: 12,
};

export function Button(props: {
  label: string;
  onPress: () => void;
  disabled?: boolean;
  danger?: boolean;
  small?: boolean;
  variant?: "primary" | "ghost";
}): React.JSX.Element {
  const classes = ["btn"];
  if (props.danger) classes.push("btn--danger");
  else if (props.variant === "ghost") classes.push("btn--ghost");
  if (props.small) classes.push("btn--small");
  return (
    <button
      type="button"
      // The portal keeps its audited contract: the handler stays attached
      // while disabled (a real browser never fires clicks on a disabled
      // button; the portal suite exercises the guard directly).
      onClick={props.onPress}
      disabled={props.disabled === true}
      className={classes.join(" ")}
    >
      {props.label}
    </button>
  );
}

export function Card(props: { children: ReactNode; deep?: boolean; title?: string; className?: string; tone?: "danger" }): React.JSX.Element {
  const classes = ["card"];
  if (props.deep) classes.push("card--deep");
  if (props.tone === "danger") classes.push("card--danger");
  if (props.className) classes.push(props.className);
  return (
    <section className={classes.join(" ")}>
      {props.title && (
        // h2 (2026-09-22, audit H-9c jest-axe suite): a Card title is a
        // view-level section directly under the page heading — the old h3
        // made every view skip a heading level (axe heading-order).
        <h2 className="card__title">{props.title}</h2>
      )}
      {props.children}
    </section>
  );
}

export function Field(props: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  placeholder?: string;
  autoComplete?: string;
}): React.JSX.Element {
  return (
    <label className="field">
      <span className="field__label">{props.label}</span>
      <input
        type={props.type ?? "text"}
        value={props.value}
        placeholder={props.placeholder}
        autoComplete={props.autoComplete}
        onChange={(e) => props.onChange(e.target.value)}
        className="input"
      />
    </label>
  );
}

export function Note(props: { children: ReactNode; tone?: "muted" | "ok" | "danger" | "warn"; role?: "status" | "alert" }): React.JSX.Element {
  const classes = ["note"];
  if (props.tone) classes.push(`note--${props.tone}`);
  // Audit fix 16 (2026-09-21): NOTE_TEMPLATES invite multi-line drafts; a
  // plain <p> collapsed the therapist's (and patient's) line breaks —
  // .note carries white-space: pre-wrap in portal.css (the inline copy of
  // the rule left with the 2026-09-26 CSP hardening, which drops
  // style-src 'unsafe-inline').
  return <p role={props.role} className={classes.join(" ")}>{props.children}</p>;
}

/** 4-segment password-strength meter under the register form's Password
 *  field (2026-09-26 UX parity with the patient web app): segments fill
 *  1–4 in the level's palette color (danger/warn/primary/ok) with a
 *  Weak/Fair/Good/Strong label. Pure presentation of a 0–4 score — the
 *  ladder (passwordStrength) lives next to the policy it mirrors, and 0
 *  renders nothing (an empty field has no strength story to tell). */
const STRENGTH_LABELS = ["Weak", "Fair", "Good", "Strong"] as const;

export function PasswordStrengthMeter(props: { strength: 0 | 1 | 2 | 3 | 4 }): React.JSX.Element | null {
  const strength = props.strength;
  if (strength === 0) return null;
  const label = STRENGTH_LABELS[strength - 1]!;
  return (
    <div className="pw-meter" role="status" aria-label={`Password strength: ${label}`}>
      {[1, 2, 3, 4].map((segment) => (
        <span
          key={segment}
          className={segment <= strength ? `pw-meter__bar pw-meter__bar--${strength}` : "pw-meter__bar"}
        />
      ))}
      <span className={`pw-meter__label pw-meter__label--${strength}`}>{label}</span>
    </div>
  );
}

export function ErrorBanner({ message }: { message: string }): React.JSX.Element | null {
  if (!message) return null;
  return (
    <div role="alert" className="banner banner--error">
      {message}
    </div>
  );
}

/** Info banner (session notices on the login screen — App.tsx). Same
 *  live-region contract as ErrorBanner: role=status announces politely,
 *  and `flush` drops the corner radius for the full-width notices App
 *  pins to the very top of the page (class-based since the 2026-09-26
 *  CSP hardening — the banner is identical DOM to the markup App used to
 *  hand-write, minus the inline style attribute). */
export function InfoBanner({ message, flush }: { message: string; flush?: boolean }): React.JSX.Element | null {
  if (!message) return null;
  return (
    <div role="status" className={flush ? "banner banner--info banner--flush" : "banner banner--info"}>
      {message}
    </div>
  );
}
