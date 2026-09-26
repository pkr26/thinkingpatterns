/**
 * Crisis resources card — one interaction from every screen, reachable in
 * every app state, and STATIC: it must never depend on the API being up
 * or on keys being unlocked (WEB_PLAN P1 skeleton; P8 expands with
 * localization and the full safe-messaging framing).
 */
import { Button, Card, Note } from "./ui";

export function CrisisCard(props: { onClose: () => void }): React.JSX.Element {
  return (
    <Card title="Get help now">
      <Note tone="danger">If you are in immediate danger, call 911 (or your local emergency number).</Note>
      <Note>988 Suicide &amp; Crisis Lifeline (US): call or text 988 — free, confidential, any hour, any day.</Note>
      <Note>Crisis Text Line: text HOME to 741741 (US, CA, UK, IE).</Note>
      <Note>Outside the US: findahelpline.com lists local, free services in your country.</Note>
      <Note tone="muted">{"Talking to a real person helps. These lines follow safe-messaging practice (#chatsafe) — what you share stays with them."}</Note>
      <Note tone="muted">You deserve support. Reaching out is a strong move.</Note>
      <Button label="Close" onPress={props.onClose} small />
    </Card>
  );
}
