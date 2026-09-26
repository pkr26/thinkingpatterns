/**
 * First-run onboarding (three panels, content mirroring the mobile app's
 * onboarding). The completion flag is a per-account non-content stamp in
 * localStorage — it names no health data, only that this browser has seen
 * the introduction for this account id.
 */
import { useState } from "react";
import { Button, Card, Note } from "../ui";

export const ONBOARDING_FLAG_PREFIX = "mindpattern.onboarding.v1.";

export function hasSeenOnboarding(userId: string, get: (key: string) => string | null): boolean {
  return get(`${ONBOARDING_FLAG_PREFIX}${userId}`) === "done";
}

export function markOnboardingSeen(userId: string, set: (key: string, value: string) => void): void {
  set(`${ONBOARDING_FLAG_PREFIX}${userId}`, "done");
}

const PANELS: { title: string; body: string }[] = [
  {
    title: "A journal that is yours alone",
    body:
      "Write daily. Everything you write is encrypted on this device before it leaves — the server stores only opaque ciphertext, forever. Not advice, not diagnosis: observations, each with its evidence.",
  },
  {
    title: "Thirty honest days",
    body:
      "Patterns need data. For your first 30 active days you will see your streak and your local mood trend — and nothing else. After the threshold, MindPattern surfaces the patterns too slow for a human to notice: weekday themes, day-after links, returning worries.",
  },
  {
    title: "You are in control",
    body:
      "Share with a therapist only if you choose (revocable, encrypted end to end). Crisis help is one tap away on every screen, offline. Export or delete everything at any time — deletion is real and immediate.",
  },
];

export function Onboarding(props: { onDone: () => void }): React.JSX.Element {
  const [step, setStep] = useState(0);
  const panel = PANELS[step]!;
  const last = step === PANELS.length - 1;
  return (
    <Card title={panel.title}>
      <Note>{panel.body}</Note>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <Button label={last ? "Start journaling" : "Next"} onPress={() => (last ? props.onDone() : setStep(step + 1))} />
        <Note tone="muted">{`Step ${step + 1} of ${PANELS.length}`}</Note>
      </div>
    </Card>
  );
}
