/**
 * First-run onboarding (three panels, content mirroring the mobile app's
 * onboarding). The completion flag is a per-account non-content stamp in
 * localStorage — it names no health data, only that this browser has seen
 * the introduction for this account id.
 *
 * Redesign 2026-09-26: progress dots, a soft abstract gradient panel per
 * step (decorative shapes only — no people imagery), and a full-width
 * continue button.
 */
import { useState } from "react";
import { t } from "../strings";
import { Button, Card, Icon, Note, ProgressDots } from "../ui";

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
  const stepLabel = t("onboarding.webStep", { current: step + 1, total: PANEL_KEYS.length });
  return (
    <div className="onboard-wrap">
      <Card title={t(panel.titleKey)}>
        {/* Soft abstract gradient panel — decorative, calm, never literal. */}
        <div className="panel-art" aria-hidden="true">
          <Icon name={step === 0 ? "shield" : step === 1 ? "book" : "heart"} size={44} />
        </div>
        <Note tone="lead">{t(panel.bodyKey)}</Note>
        {/* One progress line: the step count and the dots travel together
            (the split row read as two unrelated indicators — audit
            2026-09-26 fix). The dots carry the same aria-label. */}
        <div className="row row--wrap" style={{ gap: 10 }}>
          <ProgressDots total={PANEL_KEYS.length} current={step} label={stepLabel} />
          <span className="note note--muted">{stepLabel}</span>
        </div>
        <Button
          label={last ? t("onboarding.webStart") : t("onboarding.webNext")}
          onPress={() => (last ? props.onDone() : setStep(step + 1))}
          block
        />
      </Card>
    </div>
  );
}
