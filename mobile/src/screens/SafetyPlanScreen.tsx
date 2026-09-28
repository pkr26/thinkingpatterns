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
import { Alert, BackHandler, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import { api } from "../api/client";
import { vault } from "../vault";
import { useSession } from "../store";
import {
  emptySafetyPlan,
  loadSafetyPlan,
  saveSafetyPlan,
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

  const updatePlan = (next: SafetyPlan) => {
    planRef.current = next;
    setPlan(next);
  };

  /** Audit 2026-09-28 (MEDIUM): leaving the editor with any field differing
   *  from the loaded/saved plan used to discard SILENTLY (hardware back or
   *  the on-screen Back). A CONFIRM was chosen over silent auto-persistence
   *  by constraint: the plan is intimate, user-authored content whose only
   *  write path is the explicit Save — persisting half-finished or
   *  reconsidered text without consent would betray that contract, and a
   *  deliberate "Discard" answer keeps the user's intent explicit. */
  const planIsDirty = () => SAFETY_PLAN_FIELDS.some((field) => planRef.current[field] !== savedPlanRef.current[field]);

  const confirmDiscardPlan = (leave: () => void) => {
    if (!planIsDirty()) {
      leave();
      return;
    }
    Alert.alert(tr("safetyplan.discardTitle"), tr("safetyplan.discardBody"), [
      { text: tr("safetyplan.discardCancel"), style: "cancel" },
      { text: tr("safetyplan.discardConfirm"), style: "destructive", onPress: leave },
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
    void (async () => {
      try {
        const userId = await api.getUserId();
        if (!userId || !vault.isUnlocked()) {
          if (!cancelled) setLocked(true);
          return;
        }
        const stored = await loadSafetyPlan(vault.get().dataKey, userId);
        if (cancelled) return;
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
      } catch {
        if (!cancelled) setLocked(true);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
      if (statusTimer.current) clearTimeout(statusTimer.current);
    };
  }, []);

  // Android hardware back (audit 2026-09-28): while the editor is up with
  // unsaved changes, back is a DISCARD — confirm it like the on-screen Back
  // button. A clean plan (or the locked/loading views) lets the navigator
  // pop normally.
  useEffect(() => {
    const onBack = () => {
      if (loading || locked || !planIsDirty()) return false;
      confirmDiscardPlan(() => navigation.goBack());
      return true;
    };
    const sub = BackHandler.addEventListener("hardwareBackPress", onBack);
    return () => sub.remove();
    // Stryker disable next-line ArrayDeclaration: the handlers read refs (planRef/savedPlanRef) and stable closures; loading/locked alone gate the listener — re-running for other renders only re-attaches an identical listener
  }, [loading, locked, navigation]);

  const save = async () => {
    if (busy) return;
    touchActivity();
    setBusy(true);
    try {
      const userId = await api.getUserId();
      if (!userId) {
        Alert.alert(tr("common.sessionDamagedTitle"), tr("measures.sessionDamagedBody"));
        return;
      }
      if (!vault.isUnlocked()) {
        setLocked(true);
        Alert.alert(tr("safetyplan.lockedTitle"), tr("safetyplan.lockedBody"));
        return;
      }
      await saveSafetyPlan(vault.get().dataKey, userId, plan);
      savedPlanRef.current = plan; // the discard baseline moved with the save
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

  return (
    <ScrollView
      style={{ flex: 1, backgroundColor: t.colors.bg }}
      contentContainerStyle={{ padding: t.spacing.xl, gap: t.spacing.lg }}
      keyboardShouldPersistTaps="handled"
    >
      <Text style={{ color: t.colors.body, fontSize: t.type.bodySmall.fontSize, lineHeight: 19 }}>
        {tr("safetyplan.intro")}
      </Text>

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
                accessibilityLabel={tr(`safetyplan.field.${field}`)}
              />
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
