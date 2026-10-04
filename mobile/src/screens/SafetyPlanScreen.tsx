/**
 * The safety plan screen (2026-09-27): the local, encrypted personal plan
 * — see src/safetyPlan.ts for the structure and privacy contract.
 *
 * Reachable from the crisis screen ("Make a safety plan", always AFTER
 * the static resources) and from Settings; a MAIN-FLOW screen only (the
 * plan lives under the vault's data key). If the vault locks while this
 * screen is up, the navigator swaps to Unlock and the plaintext fields
 * unmount with it — nothing plan-shaped survives a lock in the tree.
 *
 * HONESTY ON THE SCREEN: the intro says what this is (a personal tool
 * inspired by widely used safety-planning approaches), what it is NOT (a
 * substitute for professional help), and where it lives (this device,
 * encrypted, never sent anywhere). The professionals/services field is
 * PREFILLED with the app's built-in crisis lines when the plan is new —
 * the one part of a safety plan the app can honestly contribute itself.
 */
import React, { useEffect, useRef, useState } from "react";
import { Alert, AppState, BackHandler, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import { api } from "../api/client";
import { vault } from "../vault";
import { captureLocalWritePermit, assertLocalWritePermit } from "../localRekey";
import { localWriteScopeEpoch } from "../localWriteGuard";
import { useSession } from "../store";
import {
  MAX_FIELD_CHARS,
  emptySafetyPlan,
  loadSafetyPlan,
  saveSafetyPlan,
  loadSafetyPlanDraft,
  saveSafetyPlanDraft,
  clearSafetyPlanDraft,
  SafetyPlanReadError,
  SAFETY_PLAN_FIELDS,
  type SafetyPlan,
} from "../safetyPlan";
import { useTheme } from "../theme";
import { PrimaryButton, GhostButton, CrisisHelpButton } from "../components/buttons";
import { InlineStatus, InlineStatusTone } from "../components/InlineStatus";
import { t as tr } from "../strings";

const STATUS_MS = 2_600;

export function SafetyPlanScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const { touchActivity } = useSession();
  const [plan, setPlan] = useState<SafetyPlan>(emptySafetyPlan);
  const [loading, setLoading] = useState(true);
  const [locked, setLocked] = useState(false);
  const [readFailed, setReadFailed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [statusTone, setStatusTone] = useState<InlineStatusTone>("ok");
  const statusTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  /** Live mirrors for the BackHandler subscription (audit 2026-09-28): a
   *  native-event listener outlives renders, so it must read refs, not the
   *  state captured when the listener was attached. */
  const planRef = useRef<SafetyPlan>(emptySafetyPlan());
  /** The last SAVED/LOADED plan — the baseline for "unsaved changes". */
  const savedPlanRef = useRef<SafetyPlan>(emptySafetyPlan());
  const ownerRef = useRef<string | null>(null);
  const ownerScopeRef = useRef<number | null>(null);
  const draftKeyRef = useRef<Buffer | null>(null);
  const draftTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const draftWrites = useRef<Promise<void>>(Promise.resolve());

  const persistDraft = () => {
    if (draftTimer.current) { clearTimeout(draftTimer.current); draftTimer.current = null; }
    const owner = ownerRef.current;
    if (!owner || !draftKeyRef.current || !planIsDirty()) return;
    // Preserve the original screen's ownership through its draft queue.
    if (ownerScopeRef.current !== localWriteScopeEpoch()) return;
    let writePermit;
    try { writePermit = captureLocalWritePermit(owner, draftKeyRef.current); }
    catch { return; }
    const ownedKey = Buffer.from(draftKeyRef.current);
    const snapshot = { ...planRef.current };
    draftWrites.current = draftWrites.current.catch(() => {}).then(async () => {
      try { assertLocalWritePermit(writePermit); await saveSafetyPlanDraft(ownedKey, owner, snapshot); }
      finally { ownedKey.fill(0); }
    });
    // A failed draft never masquerades as an explicitly saved plan.
    void draftWrites.current.catch(() => {});
  };

  const updatePlan = (next: SafetyPlan) => {
    planRef.current = next;
    setPlan(next);
    if (draftTimer.current) clearTimeout(draftTimer.current);
    draftTimer.current = setTimeout(persistDraft, 300);
  };

  /** Audit 2026-09-28 (MEDIUM): leaving the editor with any field differing
   *  from the loaded/saved plan used to discard SILENTLY (hardware back or
   *  the on-screen Back). A CONFIRM was chosen over silent auto-persistence
   *  by constraint: the plan is intimate, user-authored content whose only
   *  saved-plan write path remains the explicit Save. A separate encrypted
   *  draft survives interruption, and Discard removes that draft. */
  const planIsDirty = () => SAFETY_PLAN_FIELDS.some((field) => planRef.current[field] !== savedPlanRef.current[field]);

  const confirmDiscardPlan = (leave: () => void) => {
    if (!planIsDirty()) {
      leave();
      return;
    }
    Alert.alert(tr("safetyplan.discardTitle"), tr("safetyplan.discardBody"), [
      { text: tr("safetyplan.discardCancel"), style: "cancel" },
      { text: tr("safetyplan.discardConfirm"), style: "destructive", onPress: async () => {
        try {
          const owner = ownerRef.current, key = draftKeyRef.current;
          if (!owner || !key) throw new Error("The plan owner is unavailable");
          const writePermit = captureLocalWritePermit(owner, key);
          if (draftTimer.current) { clearTimeout(draftTimer.current); draftTimer.current = null; }
          draftWrites.current = draftWrites.current.catch(() => {}).then(() => clearSafetyPlanDraft(owner, writePermit));
          await draftWrites.current;
          savedPlanRef.current = planRef.current;
          leave();
        } catch { Alert.alert(tr("safetyplan.saveFailedTitle"), tr("safetyplan.saveFailedBody")); }
      } },
    ]);
  };

  const showStatus = (message: string, tone: InlineStatusTone) => {
    if (statusTimer.current) clearTimeout(statusTimer.current);
    setStatusTone(tone);
    setStatus(message);
    statusTimer.current = setTimeout(() => setStatus(null), STATUS_MS);
  };

  useEffect(() => {
    let cancelled = false;
    const hydrationEpoch = localWriteScopeEpoch(), hydrationOwner = vault.ownerUserId();
    const hydrationKey = vault.isUnlocked() ? vault.get().dataKey : null;
    const ownsHydration = () => !cancelled && hydrationEpoch === localWriteScopeEpoch() && vault.isUnlocked()
      && !!hydrationOwner && vault.ownerUserId() === hydrationOwner && vault.get().dataKey === hydrationKey;
    void (async () => {
      try {
        const userId = await api.getUserId();
        if (cancelled) return;
        if (!userId || !vault.isUnlocked()) {
          if (!cancelled) setLocked(true);
          return;
        }
        if (!ownsHydration() || userId !== hydrationOwner) throw new Error("The safety-plan account changed");
        ownerRef.current = userId;
        ownerScopeRef.current = hydrationEpoch;
        draftKeyRef.current = Buffer.from(vault.get().dataKey);
        const stored = await loadSafetyPlan(draftKeyRef.current, userId);
        if (cancelled) return;
        if (!ownsHydration()) throw new Error("The safety-plan account changed");
        if (stored !== null) {
          savedPlanRef.current = stored;
          updatePlan(stored);
        } else {
          // A NEW plan starts with the built-in crisis lines already in
          // the professionals field — the app's one honest contribution;
          // the user edits or replaces them freely. It is still the SAVED
          // baseline for the discard check until the user changes it.
          const prefilled = { ...emptySafetyPlan(), professionals: tr("safetyplan.prefillProfessionals") };
          savedPlanRef.current = prefilled;
          updatePlan(prefilled);
        }
        const draft = await loadSafetyPlanDraft(draftKeyRef.current, userId);
        if (cancelled) return;
        if (!ownsHydration()) throw new Error("The safety-plan account changed");
        if (!cancelled && draft) {
          updatePlan(draft);
          showStatus(tr("safetyplan.draftRestored"), "ok");
        }
      } catch (error) {
        if (!cancelled) {
          if (error instanceof SafetyPlanReadError) setReadFailed(true);
          else setLocked(true);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
      persistDraft();
      draftKeyRef.current?.fill(0); draftKeyRef.current = null;
      if (statusTimer.current) clearTimeout(statusTimer.current);
    };
  }, []);

  useEffect(() => {
    const subscription = AppState.addEventListener("change", state => { if (state !== "active") persistDraft(); });
    return () => subscription.remove();
  }, []);

  // Android hardware back (audit 2026-09-28): while the editor is up with
  // unsaved changes, back is a DISCARD — confirm it like the on-screen Back
  // button. A clean plan (or the locked/loading/read-failed views) lets the navigator
  // pop normally.
  useEffect(() => {
    const onBack = () => {
      if (loading || locked || readFailed || !planIsDirty()) return false;
      confirmDiscardPlan(() => navigation.goBack());
      return true;
    };
    const sub = BackHandler.addEventListener("hardwareBackPress", onBack);
    return () => sub.remove();
    // Stryker disable next-line ArrayDeclaration: the handlers read refs (planRef/savedPlanRef) and stable closures; loading/locked alone gate the listener — re-running for other renders only re-attaches an identical listener
  }, [loading, locked, readFailed, navigation]);

  // Native header back and iOS gestures must share the dirty-plan guard.
  useEffect(() => {
    if (typeof navigation.addListener !== "function") return;
    return navigation.addListener("beforeRemove", (event: any) => {
      if (!planIsDirty()) return;
      event.preventDefault();
      confirmDiscardPlan(() => {
        savedPlanRef.current = planRef.current;
        navigation.dispatch(event.data.action);
      });
    });
  }, [navigation]);

  const save = async () => {
    if (busy) return;
    touchActivity();
    setBusy(true);
    const savedSnapshot = { ...planRef.current };
    const matchesSavedSnapshot = () => SAFETY_PLAN_FIELDS.every(field => planRef.current[field] === savedSnapshot[field]);
    const submitEpoch = localWriteScopeEpoch();
    try {
      const userId = await api.getUserId();
      if (submitEpoch !== localWriteScopeEpoch()) throw new Error(tr("common.sessionDamagedTitle"));
      if (!userId) {
        Alert.alert(tr("common.sessionDamagedTitle"), tr("measures.sessionDamagedBody"));
        return;
      }
      if (!vault.isUnlocked()) {
        setLocked(true);
        Alert.alert(tr("safetyplan.lockedTitle"), tr("safetyplan.lockedBody"));
        return;
      }
      if (vault.ownerUserId() !== userId) throw new Error(tr("common.sessionDamagedTitle"));
      if (ownerRef.current !== userId || ownerScopeRef.current !== submitEpoch) throw new Error(tr("common.sessionDamagedTitle"));
      const dataKey = vault.get().dataKey;
      const writePermit = captureLocalWritePermit(userId, dataKey);
      await saveSafetyPlan(dataKey, userId, savedSnapshot);
      savedPlanRef.current = savedSnapshot;
      if (matchesSavedSnapshot() && draftTimer.current) { clearTimeout(draftTimer.current); draftTimer.current = null; }
      // Serialize ACK removal with draft writes and leave later edits
      // recoverable rather than acknowledging a different editor state.
      draftWrites.current = draftWrites.current.catch(() => {}).then(async () => {
        if (matchesSavedSnapshot()) await clearSafetyPlanDraft(userId, writePermit);
      });
      await draftWrites.current;
      if (!matchesSavedSnapshot()) persistDraft();
      showStatus(tr("safetyplan.saved"), "ok");
    } catch {
      // Nothing was lost: the fields are still on screen exactly as typed.
      Alert.alert(tr("safetyplan.saveFailedTitle"), tr("safetyplan.saveFailedBody"));
    } finally {
      setBusy(false);
    }
  };

  if (locked) {
    return (
      <ScrollView
        style={{ flex: 1, backgroundColor: t.colors.bg }}
        contentContainerStyle={{ padding: t.spacing.xl, gap: t.spacing.lg }}
      >
        <Text style={{ color: t.colors.text, fontSize: t.type.title.fontSize, fontWeight: "700" }}>
          {tr("safetyplan.lockedTitle")}
        </Text>
        <Text style={{ color: t.colors.body, fontSize: t.type.bodySmall.fontSize, lineHeight: 19 }}>
          {tr("safetyplan.lockedBody")}
        </Text>
        {/* Static crisis help stays reachable from here, pre-unlock as ever. */}
        <GhostButton label={tr("buttons.needHelp")} onPress={() => navigation.navigate("Crisis")} />
      </ScrollView>
    );
  }

  if (readFailed) {
    return (
      <ScrollView
        style={{ flex: 1, backgroundColor: t.colors.bg }}
        contentContainerStyle={{ padding: t.spacing.xl, gap: t.spacing.lg }}
      >
        <Text style={{ color: t.colors.text, fontSize: t.type.title.fontSize, fontWeight: "700" }}>
          {tr("safetyplan.readFailedTitle")}
        </Text>
        <Text style={{ color: t.colors.body, fontSize: t.type.bodySmall.fontSize, lineHeight: 19 }}>
          {tr("safetyplan.readFailedBody")}
        </Text>
        <GhostButton label={tr("common.back")} onPress={() => navigation.goBack()} />
        <GhostButton label={tr("buttons.needHelp")} onPress={() => navigation.navigate("Crisis")} />
      </ScrollView>
    );
  }

  return (
    <ScrollView
      style={{ flex: 1, backgroundColor: t.colors.bg }}
      contentContainerStyle={{ padding: t.spacing.xl, gap: t.spacing.lg }}
      keyboardShouldPersistTaps="handled"
    >
      <Text style={{ color: t.colors.body, fontSize: t.type.bodySmall.fontSize, lineHeight: 19 }}>
        {tr("safetyplan.intro")}
      </Text>
      <Text style={{ color: t.colors.muted, fontSize: t.type.bodySmall.fontSize }}>{tr("safetyplan.draftInfo")}</Text>

      {loading ? null : (
        <>
          {SAFETY_PLAN_FIELDS.map((field, index) => (
            <View key={field} style={{ gap: t.spacing.sm }}>
              <Text style={{ color: t.colors.text, fontSize: t.type.body.fontSize, fontWeight: "600" }}>
                {index + 1}. {tr(`safetyplan.field.${field}`)}
              </Text>
              <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>
                {tr(`safetyplan.hint.${field}`)}
              </Text>
              <TextInput
                style={planInputStyle(t)}
                value={plan[field]}
                onChangeText={(text) => {
                  touchActivity();
                  updatePlan({ ...plan, [field]: text });
                }}
                multiline
                maxLength={MAX_FIELD_CHARS}
                autoCorrect={false}
                spellCheck={false}
                textContentType="none"
                accessibilityLabel={tr(`safetyplan.field.${field}`)}
              />
              <Text style={{ color: plan[field].length > MAX_FIELD_CHARS ? t.colors.error : t.colors.muted }}>{plan[field].length}/{MAX_FIELD_CHARS}</Text>
            </View>
          ))}

          <PrimaryButton label={tr("safetyplan.save")} onPress={save} busy={busy} />
          <InlineStatus message={status} tone={statusTone} />
        </>
      )}
      {/* Audit 2026-09-28 (MEDIUM): Back with unsaved changes confirms the
          discard (see confirmDiscardPlan for why confirm, not persistence). */}
      <GhostButton label={tr("common.back")} onPress={() => confirmDiscardPlan(() => navigation.goBack())} center={false} />
      {/* Audit 2026-09-28 (INFO): the crisis affordance every other screen
          carries — a safety-plan editor is exactly where it belongs. */}
      <CrisisHelpButton onPress={() => navigation.navigate("Crisis")} />
    </ScrollView>
  );
}

/** The plan field style resolves per theme (the LoginScreen inputTheme
 *  idiom — a function, not a StyleSheet entry, so it composes with the
 *  active palette). */
function planInputStyle(t: ReturnType<typeof useTheme>) {
  return {
    backgroundColor: t.colors.card,
    color: t.colors.text,
    borderRadius: t.radius.md,
    padding: 14,
    fontSize: 15,
    minHeight: 72,
    textAlignVertical: "top" as const,
  };
}
