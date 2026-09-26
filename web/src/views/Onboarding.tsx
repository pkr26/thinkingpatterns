/**
 * First-run onboarding (three panels, content mirroring the mobile app's
 * onboarding). The completion flag is a per-account non-content stamp in
 * localStorage — it names no health data, only that this browser has seen
 * the introduction for this account id.
 */
import { useState } from "react";
import { t } from "../strings";
import { Button, Card, Note } from "../ui";

export const ONBOARDING_FLAG_PREFIX = "mindpattern.onboarding.v1.";

export function hasSeenOnboarding(userId: string, get: (key: string) => string | null): boolean {
  return get(`${ONBOARDING_FLAG_PREFIX}${userId}`) === "done";
}

export function markOnboardingSeen(userId: string, set: (key: string, value: string) => void): void {
  set(`${ONBOARDING_FLAG_PREFIX}${userId}`, "done");
}

/** M-W5 (audit 2026-09-26): panel copy resolves through the t() catalog —
 *  catalog KEYS here, never inline English. */
const PANEL_KEYS: { titleKey: string; bodyKey: string }[] = [
  { titleKey: "onboarding.webPanel1Title", bodyKey: "onboarding.webPanel1Body" },
  { titleKey: "onboarding.webPanel2Title", bodyKey: "onboarding.webPanel2Body" },
  { titleKey: "onboarding.webPanel3Title", bodyKey: "onboarding.webPanel3Body" },
];

export function Onboarding(props: { onDone: () => void }): React.JSX.Element {
  const [step, setStep] = useState(0);
  const panel = PANEL_KEYS[step]!;
  const last = step === PANEL_KEYS.length - 1;
  return (
    <Card title={t(panel.titleKey)}>
      <Note>{t(panel.bodyKey)}</Note>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <Button label={last ? t("onboarding.webStart") : t("onboarding.webNext")} onPress={() => (last ? props.onDone() : setStep(step + 1))} />
        <Note tone="muted">{t("onboarding.webStep", { current: step + 1, total: PANEL_KEYS.length })}</Note>
      </div>
    </Card>
  );
}
