/**
 * Accessible clinician-facing UI components styled by public/portal.css.
 * Cards use section headings, fields have associated labels, notes preserve
 * line breaks, and banners expose live regions. The exported theme mirrors
 * CSS tokens for SVG stroke and fill attributes.
 */
import { useId, useState, type ReactNode } from "react";

/** CSS token mirror for SVGs; designTokens.test.ts verifies palette parity. */
export const theme = {
  bg: "#211e1a",
  card: "#2a2620",
  cardDeep: "#232019",
  text: "#ede8df",
  body: "#cfc7ba",
  muted: "#a29a8c",
  accent: "#a9cba4",
  accentBright: "#b7d5b2",
  danger: "#eba49b",
  ok: "#93c7a6",
  warn: "#dcae6c",
  border: "#3a352c",
  radius: 12,
};

export function Button(props: {
  label: string;
  onPress?: () => void;
  disabled?: boolean;
  danger?: boolean;
  small?: boolean;
  variant?: "primary" | "ghost";
  /** Submit buttons delegate to the form and must omit onPress to avoid
   * firing both the click handler and form submission. */
  type?: "button" | "submit";
}): React.JSX.Element {
  const classes = ["btn"];
  if (props.danger) classes.push("btn--danger");
  else if (props.variant === "ghost") classes.push("btn--ghost");
  if (props.small) classes.push("btn--small");
  if (props.type === "submit" && props.onPress) {
    throw new Error("a submit button must not carry its own onPress (double-fire)");
  }
  return (
    <button
      type={props.type ?? "button"}
      // Native disabled buttons suppress clicks; action handlers also guard reentry.
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
        // Card sections sit directly below the page's h1.
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
  /** Show an accessible visibility toggle beside password fields. */
  reveal?: boolean;
}): React.JSX.Element {
  const [shown, setShown] = useState(false);
  const inputId = useId();
  const isPassword = (props.type ?? "text") === "password";
  const type = isPassword && shown ? "text" : props.type ?? "text";
  const input = (
    <input
      id={inputId}
      type={type}
      value={props.value}
      placeholder={props.placeholder}
      autoComplete={props.autoComplete}
      onChange={(e) => props.onChange(e.target.value)}
      className="input"
    />
  );
  return (
    <div className="field">
      <label className="field__label" htmlFor={inputId}>{props.label}</label>
      {props.reveal && isPassword ? (
        <span className="field__row">
          {input}
          <Button
            label={shown ? "Hide password" : "Show password"}
            small
            variant="ghost"
            onPress={() => setShown((v) => !v)}
          />
        </span>
      ) : (
        input
      )}
    </div>
  );
}

/** Native disclosure for longer policy text; expanded state stays user-controlled. */
export function Disclosure(props: { summary: string; children: ReactNode }): React.JSX.Element {
  return (
    <details className="disclose">
      <summary>{props.summary}</summary>
      <div className="disclose__body">
        <Note tone="muted">{props.children}</Note>
      </div>
    </details>
  );
}

export function Note(props: { children: ReactNode; tone?: "muted" | "ok" | "danger" | "warn"; role?: "status" | "alert" }): React.JSX.Element {
  const classes = ["note"];
  if (props.tone) classes.push(`note--${props.tone}`);
  // portal.css preserves user-authored line breaks with white-space: pre-wrap.
  return <p role={props.role} className={classes.join(" ")}>{props.children}</p>;
}

/** Four-segment presentation of the policy score; an empty password has no meter. */
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

/** Polite status banner; flush removes rounded corners for page-wide notices. */
export function InfoBanner({ message, flush }: { message: string; flush?: boolean }): React.JSX.Element | null {
  if (!message) return null;
  return (
    <div role="status" className={flush ? "banner banner--info banner--flush" : "banner banner--info"}>
      {message}
    </div>
  );
}
