/**
 * The privacy screen — plain-language account of what the server can and
 * cannot see (the README's "security model, honest version" distilled for
 * the person journaling). Static content; no network. M-W5 (audit
 * 2026-09-26): the copy resolves through the t() catalog.
 */
import { t } from "../strings";
import { Button, Card, Note } from "../ui";

export function Privacy(props: { onBack: () => void }): React.JSX.Element {
  return (
    <Card title={t("privacy.webTitle")}>
      <Note>{t("privacy.webS1")}</Note>
      <Note>{t("privacy.webS2")}</Note>
      <Note>{t("privacy.webS3")}</Note>
      <Note>{t("privacy.webS4")}</Note>
      <Note tone="muted">{t("privacy.webS5")}</Note>
      {/* Row wrapper so the button hugs its label: Card is a flex column,
          and a bare stretch child renders ~1000px wide (E2E 2026-09-26,
          finding F2) — every other view wraps its buttons this way. */}
      <div style={{ display: "flex", gap: 8 }}>
        <Button label={t("common.back")} onPress={props.onBack} small />
      </div>
    </Card>
  );
}
