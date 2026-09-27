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
import { Alert, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
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
import { PrimaryButton, GhostButton } from "../components/buttons";
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
          setPlan(stored);
        } else {
          // A NEW plan starts with the built-in crisis lines already in
          // the professionals field — the app's one honest contribution;
          // the user edits or replaces them freely.
          setPlan({ ...emptySafetyPlan(), professionals: tr("safetyplan.prefillProfessionals") });
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
                  setPlan((previous) => ({ ...previous, [field]: text }));
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
      <GhostButton label={tr("common.back")} onPress={() => navigation.goBack()} center={false} />
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
