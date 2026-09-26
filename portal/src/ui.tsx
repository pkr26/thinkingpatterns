/**
 * UI kit — calm, clinical, no dependencies (redesign 2026-09-26).
 * Components render through the token-driven classes in public/portal.css;
 * the `theme` object stays exported (refreshed values + the previously
 * MISSING `warn` token) because the views carry inline styles that read
 * it — those inline styles now pick up the refined palette automatically.
 *
 * Contracts kept: Buttons are real <button>s whose handler is absent when
 * disabled; cards are sections with h2 titles; Field wraps its input in
 * the label; Note preserves line breaks; ErrorBanner announces with
 * role=alert.
 */
import type { ReactNode } from "react";

/** Mirrors the CSS custom properties in public/portal.css. The `warn`
 *  token is new (the old kit rendered warn Notes in accent blue — tone
 *  drift the redesign corrects). */
export const theme = {
  bg: "#0d1219",
  card: "#151b28",
  cardDeep: "#101622",
  text: "#e8edf6",
  body: "#c6cfdd",
  muted: "#8a95a3",
  accent: "#4f8cff",
  accentBright: "#7db0ff",
  danger: "#e5685a",
  ok: "#55b384",
  warn: "#d9a35e",
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

export function Note(props: { children: ReactNode; tone?: "muted" | "ok" | "danger" | "warn"; role?: "status" }): React.JSX.Element {
  const classes = ["note"];
  if (props.tone) classes.push(`note--${props.tone}`);
  // Audit fix 16 (2026-09-21): NOTE_TEMPLATES invite multi-line drafts; a
  // plain <p> collapsed the therapist's (and the patient's) line breaks.
  return <p role={props.role} className={classes.join(" ")} style={{ whiteSpace: "pre-wrap" }}>{props.children}</p>;
}

export function ErrorBanner({ message }: { message: string }): React.JSX.Element | null {
  if (!message) return null;
  return (
    <div role="alert" className="banner banner--error">
      {message}
    </div>
  );
}

/** Info banner (session notices on the login screen — App.tsx). */
export function InfoBanner({ message }: { message: string }): React.JSX.Element | null {
  if (!message) return null;
  return <div className="banner banner--info">{message}</div>;
}
