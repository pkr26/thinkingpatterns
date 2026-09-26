/**
 * Minimal UI kit — calm, light, patient-facing, no dependencies. Buttons
 * are real <button>s (keyboard accessibility for free); cards are
 * sections with h2 titles (no skipped heading levels). Forked from the
 * portal's kit with a patient theme (WEB_PLAN P1.5).
 */
import type { ReactNode } from "react";

export const theme = {
  bg: "#f5f7fa",
  card: "#ffffff",
  cardDeep: "#eef2f7",
  text: "#1c2430",
  body: "#3d4a5c",
  muted: "#748294",
  accent: "#3d6fb4",
  accentBright: "#5a8fd6",
  danger: "#c0453a",
  ok: "#3f8f68",
  warn: "#b07d2b",
  border: "#dfe5ec",
  radius: 12,
};

export function Button(props: {
  label: string;
  onPress: () => void;
  disabled?: boolean;
  danger?: boolean;
  small?: boolean;
}): React.JSX.Element {
  return (
    <button
      type="button"
      // The handler is not merely ignored — it is absent — when disabled,
      // so no synthetic click path can fire it.
      onClick={props.disabled ? undefined : props.onPress}
      disabled={props.disabled === true}
      style={{
        backgroundColor: props.danger ? theme.danger : theme.accent,
        color: "#fff",
        border: "none",
        borderRadius: theme.radius,
        padding: props.small ? "6px 12px" : "10px 16px",
        fontSize: props.small ? 13 : 15,
        fontWeight: 600,
        cursor: props.disabled ? "default" : "pointer",
        opacity: props.disabled ? 0.5 : 1,
      }}
    >
      {props.label}
    </button>
  );
}

export function Card(props: { children: ReactNode; deep?: boolean; title?: string }): React.JSX.Element {
  return (
    <section
      style={{
        backgroundColor: props.deep ? theme.cardDeep : theme.card,
        borderRadius: theme.radius,
        border: `1px solid ${theme.border}`,
        padding: 16,
        display: "flex",
        flexDirection: "column",
        gap: 10,
      }}
    >
      {props.title && <h2 style={{ margin: 0, color: theme.text, fontSize: 15, fontWeight: 600 }}>{props.title}</h2>}
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
    <label style={{ display: "flex", flexDirection: "column", gap: 4, color: theme.muted, fontSize: 12, fontWeight: 700 }}>
      {props.label}
      <input
        type={props.type ?? "text"}
        value={props.value}
        placeholder={props.placeholder}
        autoComplete={props.autoComplete}
        onChange={(e) => props.onChange(e.target.value)}
        style={{
          backgroundColor: theme.cardDeep,
          color: theme.text,
          border: `1px solid ${theme.border}`,
          borderRadius: theme.radius,
          padding: "10px 12px",
          fontSize: 15,
          fontWeight: 400,
        }}
      />
    </label>
  );
}

/** Multi-line journal editor. The label is wrapped like Field's so the
 *  control stays programmatically findable in tests and for a11y. */
export function TextArea(props: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  rows?: number;
}): React.JSX.Element {
  return (
    <label style={{ display: "flex", flexDirection: "column", gap: 4, color: theme.muted, fontSize: 12, fontWeight: 700 }}>
      {props.label}
      <textarea
        value={props.value}
        placeholder={props.placeholder}
        rows={props.rows ?? 8}
        onChange={(e) => props.onChange(e.target.value)}
        style={{
          backgroundColor: theme.cardDeep,
          color: theme.text,
          border: `1px solid ${theme.border}`,
          borderRadius: theme.radius,
          padding: "10px 12px",
          fontSize: 15,
          fontWeight: 400,
          fontFamily: "inherit",
          lineHeight: 1.5,
          resize: "vertical",
        }}
      />
    </label>
  );
}

export function Note(props: { children: ReactNode; tone?: "muted" | "ok" | "danger" | "warn"; role?: "status" }): React.JSX.Element {
  const color =
    props.tone === "ok" ? theme.ok
      : props.tone === "danger" ? theme.danger
        : props.tone === "warn" ? theme.warn
          : theme.muted;
  // Journal text and prompts are multi-line by nature; line breaks must
  // survive rendering.
  return <p role={props.role} style={{ margin: 0, color, fontSize: 13, lineHeight: 1.5, whiteSpace: "pre-wrap" }}>{props.children}</p>;
}

export function ErrorBanner({ message }: { message: string }): React.JSX.Element | null {
  if (!message) return null;
  return (
    <div
      role="alert"
      style={{
        backgroundColor: "#fbeeea",
        color: "#8f3a32",
        border: `1px solid ${theme.danger}`,
        borderRadius: theme.radius,
        padding: "10px 14px",
        fontSize: 14,
      }}
    >
      {message}
    </div>
  );
}

/** App chrome: sticky header (product name + the crisis entry point that
 *  must be one interaction from every screen — WEB_PLAN P8.1, present
 *  from day one) and the responsive content column from index.html's
 *  breakpoint skeleton. */
export function AppFrame(props: { title: string; onCrisis: () => void; children: ReactNode }): React.JSX.Element {
  return (
    <>
      {/* The skip link is the first tabbable element; visual users never
          see it until it has focus (keyboard a11y floor, P8.3). */}
      <a href="#app-content" style={{ position: "absolute", left: -9999, top: 0, background: theme.card, color: theme.text, padding: "8px 12px", zIndex: 100 }}>Skip to content</a>
      <header className="app-header">
        <h1 style={{ margin: 0, fontSize: 17, fontWeight: 700, color: theme.text }}>{props.title}</h1>
        <Button label="Get help" onPress={props.onCrisis} small />
      </header>
      <main className="app-main" id="app-content">{props.children}</main>
    </>
  );
}
