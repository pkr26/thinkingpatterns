/**
 * Minimal UI kit — calm, clinical, no dependencies. Buttons are real
 * <button>s (keyboard accessibility for free); cards are sections.
 */
import type { ReactNode } from "react";

export const theme = {
  bg: "#0d1117",
  card: "#161b26",
  cardDeep: "#10141d",
  text: "#e7ecf5",
  body: "#c3ccdb",
  muted: "#7d8899",
  accent: "#4f8cff",
  accentBright: "#6ea0ff",
  danger: "#e0604f",
  ok: "#4fae7c",
  border: "#232a38",
  radius: 10,
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
      onClick={props.onPress}
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
      {props.title && (
        <h3 style={{ margin: 0, color: theme.text, fontSize: 15, fontWeight: 600 }}>{props.title}</h3>
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
}): React.JSX.Element {
  return (
    <label style={{ display: "flex", flexDirection: "column", gap: 4, color: theme.muted, fontSize: 12, fontWeight: 700 }}>
      {props.label}
      <input
        type={props.type ?? "text"}
        value={props.value}
        placeholder={props.placeholder}
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

export function Note(props: { children: ReactNode; tone?: "muted" | "ok" | "danger" }): React.JSX.Element {
  const color = props.tone === "ok" ? theme.ok : props.tone === "danger" ? theme.danger : theme.muted;
  return <p style={{ margin: 0, color, fontSize: 13, lineHeight: 1.5 }}>{props.children}</p>;
}

export function ErrorBanner({ message }: { message: string }): React.JSX.Element | null {
  if (!message) return null;
  return (
    <div
      role="alert"
      style={{
        backgroundColor: "#2a1a17",
        color: "#f0b6ad",
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
