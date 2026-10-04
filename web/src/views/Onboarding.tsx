/**
 * First-run onboarding (three panels, content mirroring the mobile app's
 * onboarding). The completion flag is a per-account non-content stamp in
 * generation-fenced IndexedDB — it names no health data, but still cannot
 * be recreated by a stale tab after confirmed account erasure.
 *
 * Redesign 2026-09-26: progress dots, a soft abstract gradient panel per
 * step (decorative shapes only — no people imagery), and a full-width
 * continue button.
 */
// @ts-nocheck

import { useState } from "react";
import { t } from "../strings";
import { Button, Card, Icon, Note, ProgressDots } from "../ui";
import { kv } from "../kvstore";
import { localStore } from "../platform";

export const ONBOARDING_FLAG_PREFIX = "mindpattern.onboarding.v1.";

const onboardingKey = (userId: string): string => `${ONBOARDING_FLAG_PREFIX}${userId}`;

export async function hasSeenOnboarding(userId: string): Promise<boolean> {
  const key = onboardingKey(userId);
  if (await kv.getItem(key) === "done") return true;
  // One-way migration from the pre-fence localStorage stamp. Commit to KV
  // first; a deleted generation rejects it and the stale stamp is never
  // treated as durable current-account state.
  if (localStore.get(key) !== "done") return false;
  await kv.setItem(key, "done");
  localStore.remove(key);
  return true;
}

export async function markOnboardingSeen(userId: string): Promise<void> {
  await kv.setItem(onboardingKey(userId), "done");
}

export async function clearOnboardingSeen(userId: string): Promise<void> {
  await kv.removeItem(onboardingKey(userId));
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
