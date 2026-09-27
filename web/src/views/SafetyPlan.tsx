/**
 * The safety plan editor (clinical review 2026-09-27): a minimal,
 * Stanley-Brown-inspired structure the patient writes themselves —
 * warning signs, what helps, people and places, who to ask, who to
 * contact, making the environment safer.
 *
 * CUSTODY, stated where it is edited: the plan is encrypted under the
 * data key on this device (safetyPlan.ts) and is never synced, exported,
 * or shared — not even with a therapist. The professionals field carries
 * only a HINT listing the crisis lines the app already shows everywhere;
 * the stored words are the patient's own.
 *
 * Reachable from the crisis dialog ("Make a safety plan", only while
 * unlocked — the plan is ciphertext otherwise) and from Settings. The
 * crisis resources stay one tap away from here too: the Get help button
 * in this view opens the same static dialog.
 */
import { useEffect, useRef, useState } from "react";
import { EMPTY_SAFETY_PLAN, loadSafetyPlan, saveSafetyPlan, type SafetyPlan } from "../safetyPlan";
import { t } from "../strings";
import { vault } from "../vault";
import { Button, Card, ErrorBanner, Note, TextArea } from "../ui";

/** Display order + the locale key behind each field prompt. */
const FIELDS: { field: keyof SafetyPlan; labelKey: string; placeholderKey?: string }[] = [
  { field: "warningSigns", labelKey: "plan.warningSigns", placeholderKey: "plan.warningSignsHint" },
  { field: "coping", labelKey: "plan.coping", placeholderKey: "plan.copingHint" },
  { field: "peoplePlaces", labelKey: "plan.peoplePlaces", placeholderKey: "plan.peoplePlacesHint" },
  { field: "helpers", labelKey: "plan.helpers", placeholderKey: "plan.helpersHint" },
  { field: "professionals", labelKey: "plan.professionals", placeholderKey: "plan.professionalsHint" },
  { field: "saferEnvironment", labelKey: "plan.saferEnvironment", placeholderKey: "plan.saferEnvironmentHint" },
];

export function SafetyPlanView(props: { onCrisis: () => void }): React.JSX.Element {
  const [plan, setPlan] = useState<SafetyPlan>(EMPTY_SAFETY_PLAN);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [savedNote, setSavedNote] = useState<string | null>(null);
  const generation = useRef(0);

  useEffect(() => {
    const run = generation.current + 1;
    generation.current = run;
    void (async () => {
      const owner = vault.ownerUserId();
      if (!owner || !vault.isUnlocked()) return;
      const stored = await loadSafetyPlan(vault.get().dataKey, owner);
      if (generation.current === run && stored !== null) setPlan(stored);
    })().catch(() => {
      // Locked vault / dead storage: the blank editor is the honest state.
    });
  }, []);

  const save = async (): Promise<void> => {
    const owner = vault.ownerUserId();
    if (!owner || !vault.isUnlocked()) {
      setError(t("common.sessionLocked"));
      return;
    }
    setBusy(true);
    setError("");
    try {
      await saveSafetyPlan(vault.get().dataKey, owner, plan);
      setSavedNote(t("plan.savedNote"));
    } catch (err) {
      setSavedNote(null);
      setError(err instanceof Error ? err.message : t("plan.saveFailed"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title={t("plan.title")} tone="sensitive">
      <Note tone="muted">{t("plan.intro")}</Note>
      {FIELDS.map(({ field, labelKey, placeholderKey }) => (
        <TextArea
          key={field}
          label={t(labelKey)}
          value={plan[field]}
          onChange={(value) => {
            setSavedNote(null);
            setPlan((current) => ({ ...current, [field]: value }));
          }}
          placeholder={placeholderKey ? t(placeholderKey) : undefined}
          rows={3}
        />
      ))}
      <ErrorBanner message={error} />
      {savedNote && <Note role="status" tone="ok">{savedNote}</Note>}
      <div className="row row--wrap">
        <Button label={busy ? t("entry.saving") : t("plan.save")} onPress={() => void save()} disabled={busy} />
        <Button label={t("nav.getHelp")} onPress={props.onCrisis} small variant="ghost" icon="phone" />
      </div>
      <Note tone="muted">{t("plan.localNote")}</Note>
    </Card>
  );
}
