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
// @ts-nocheck

import { useEffect, useRef, useState } from "react";
import { EMPTY_SAFETY_PLAN, FIELD_MAX, loadSafetyPlan, saveSafetyPlan, type SafetyPlan } from "../safetyPlan";
import { displayError } from "../errors";
import { t } from "../strings";
import { vault } from "../vault";
import { registerSafetyPlanSource } from "../safetyPlan";
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
  // 2026-10-01 audit M11: the live plan, dirty-tracked. planRef feeds the
  // lock/crash/navigation seal (safetyPlan.registerSafetyPlanSource); the
  // dirty flag keeps a CLEAN editor from re-sealing over itself, while a
  // dirty one survives every lock/crash that used to destroy it.
  const planRef = useRef<SafetyPlan>(plan);
  planRef.current = plan;
  const dirtyRef = useRef(false);
  const dirtyFields = useRef(new Set<keyof SafetyPlan>());
  const hydratedRef = useRef(false);
  useEffect(
    () =>
      registerSafetyPlanSource(() => (dirtyRef.current && hydratedRef.current ? planRef.current : null)),
    [],
  );

  const [hydrated,setHydrated] = useState(false);
  const restore = async (): Promise<void> => {
    const run = ++generation.current; const owner = vault.ownerUserId();
    if (!owner || !vault.isUnlocked()) return;
    setError("");
    try {
      const stored = await loadSafetyPlan(vault.get().dataKey,owner);
      if (generation.current !== run) return;
      if (stored !== null) setPlan(current => {
        const restored = {...stored};
        for (const field of dirtyFields.current) restored[field] = current[field];
        return restored;
      });
      hydratedRef.current = true; setHydrated(true);
    } catch (err) { if (generation.current === run) setError(displayError(err, t("plan.saveFailed"))); }
  };
  useEffect(() => { void restore(); return () => { generation.current += 1; }; },[]);

  const save = async (): Promise<void> => {
    if (!hydrated) { setError(t("plan.restoreFirst")); return; }
    const owner = vault.ownerUserId();
    if (!owner || !vault.isUnlocked()) {
      setError(t("common.sessionLocked"));
      return;
    }
    setBusy(true);
    setError("");
    try {
      const submitted = planRef.current;
      await saveSafetyPlan(vault.get().dataKey, owner, submitted);
      if (planRef.current === submitted) {
        dirtyRef.current = false;
        dirtyFields.current.clear();
        setSavedNote(t("plan.savedNote"));
      }
    } catch (err) {
      setSavedNote(null);
      setError(displayError(err, t("plan.saveFailed")));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title={t("plan.title")} tone="sensitive">
      <Note tone="muted">{t("plan.intro")}</Note>
      {!hydrated && <Button label={t("plan.retryRestore")} onPress={() => void restore()} small />}
      {FIELDS.map(({ field, labelKey, placeholderKey }) => (
        <TextArea
          key={field}
          label={t(labelKey)}
          value={plan[field]}
          onChange={(value) => {
            setSavedNote(null);
            dirtyRef.current = true;
            dirtyFields.current.add(field);
            setPlan((current) => ({ ...current, [field]: value }));
          }}
          placeholder={placeholderKey ? t(placeholderKey) : undefined}
          rows={3}
          maxLength={FIELD_MAX}
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
