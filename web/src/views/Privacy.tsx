/**
 * The privacy screen — plain-language account of what the server can and
 * cannot see (the README's "security model, honest version" distilled for
 * the person journaling). Static content; no network.
 */
import { Button, Card, Note } from "../ui";

export function Privacy(props: { onBack: () => void }): React.JSX.Element {
  return (
    <Card title="Privacy, honestly">
      <Note>{"What this app encrypts: everything you write. Your password derives a key on this device; entries, patterns, questions and measures travel and rest as opaque ciphertext the server cannot read."}</Note>
      <Note>{"What the server does hold: your username, the dates and sizes of entries, and insight dates. A database leak reveals when and how much you wrote — never what."}</Note>
      <Note>{"One deliberate exception: when you press \"Refresh patterns\", your key travels inside a single-use processing session over TLS, is held in memory only, and is destroyed the moment the analysis consumes it."}</Note>
      <Note>{"Sharing with a therapist is opt-in, encrypted end to end, and revocable. Revoking ends access immediately; it cannot unread what was already seen."}</Note>
      <Note tone="muted">{"Deletion removes you and the full cascade from the live database. Only the access audit log (who read what, when — no content) survives, for accountability."}</Note>
      {/* Row wrapper so the button hugs its label: Card is a flex column,
          and a bare stretch child renders ~1000px wide (E2E 2026-09-26,
          finding F2) — every other view wraps its buttons this way. */}
      <div style={{ display: "flex", gap: 8 }}>
        <Button label="Back" onPress={props.onBack} small />
      </div>
    </Card>
  );
}
