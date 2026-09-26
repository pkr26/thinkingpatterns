/**
 * Crisis resources card — one interaction from every screen, reachable in
 * every app state, and STATIC: it must never depend on the API being up
 * or on keys being unlocked (WEB_PLAN P1 skeleton; P8 expands with
 * localization and the full safe-messaging framing).
 *
 * M-W5 (audit 2026-09-26): the copy resolves through the t() catalog — a
 * Spanish device reads Spanish support copy. SAFETY-CRITICAL invariant
 * carried from the catalogs: phone numbers, short codes and URLs (911,
 * 988, 741741, findahelpline.com) are NEVER translated.
 */
import { t } from "./strings";
import { Button, Card, Note } from "./ui";

export function CrisisCard(props: { onClose: () => void }): React.JSX.Element {
  return (
    <Card title={t("crisis.webTitle")}>
      <Note tone="danger">{t("crisis.webImmediate")}</Note>
      <Note>{t("crisis.web988")}</Note>
      <Note>{t("crisis.webTextLine")}</Note>
      <Note>{t("crisis.webOutsideUS")}</Note>
      <Note tone="muted">{t("crisis.webSafeMessaging")}</Note>
      <Note tone="muted">{t("crisis.webYouDeserve")}</Note>
      <Button label={t("common.close")} onPress={props.onClose} small />
    </Card>
  );
}
