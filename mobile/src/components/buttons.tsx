/**
 * Shared buttons. Every interactive element in the app goes through these
 * (or declares the same props itself): accessibilityRole + label + state,
 * and a ≥ 44pt touch target. Visual language comes from the theme — no hex
 * literals here.
 */
import React from "react";
import { ActivityIndicator, StyleSheet, Text, TouchableOpacity } from "react-native";
import { useTheme } from "../theme";
import { t } from "../strings";

interface PressableProps {
  onPress: () => void;
  disabled?: boolean;
  /** Screen-reader text; defaults to the visible label. */
  accessibilityLabel?: string;
}

interface ButtonProps extends PressableProps {
  label: string;
  /** Show a spinner instead of the label (in-flight work). */
  busy?: boolean;
}

/** The one filled call-to-action on a screen. White label on the AA-passing
 *  primary fill; a danger variant for destructive actions. */
export function PrimaryButton({ label, onPress, disabled, busy, danger, accessibilityLabel }: ButtonProps & { danger?: boolean }) {
  const t = useTheme();
  const isDisabled = Boolean(disabled || busy);
  return (
    <TouchableOpacity
      style={[
        styles.primary,
        { backgroundColor: danger ? t.colors.danger : t.colors.primary, minHeight: t.minTouch },
        isDisabled && styles.dimmed,
      ]}
      onPress={onPress}
      disabled={isDisabled}
      accessibilityRole="button"
      accessibilityLabel={accessibilityLabel ?? label}
      accessibilityState={{ disabled: isDisabled, busy: Boolean(busy) }}
    >
      {busy ? (
        <ActivityIndicator color={t.colors.onPrimary} />
      ) : (
        <Text style={[styles.primaryText, { color: t.colors.onPrimary, fontSize: t.type.bodyLarge.fontSize }]}>{label}</Text>
      )}
    </TouchableOpacity>
  );
}

/** A quiet text action ("Sign out instead", mode switches). No fill; the
 *  hitSlop guarantees the 44pt target the bare text cannot. */
export function GhostButton({ label, onPress, disabled, accessibilityLabel, center = true }: ButtonProps & { center?: boolean }) {
  const t = useTheme();
  return (
    <TouchableOpacity
      style={[styles.ghost, center && styles.centered, { minHeight: t.minTouch }]}
      onPress={onPress}
      disabled={Boolean(disabled)}
      hitSlop={t.touchSlop}
      accessibilityRole="button"
      accessibilityLabel={accessibilityLabel ?? label}
      accessibilityState={{ disabled: Boolean(disabled) }}
    >
      <Text style={{ color: t.colors.muted, fontSize: 14 }}>{label}</Text>
    </TouchableOpacity>
  );
}

/** Crisis help is NOT ordinary navigation: it gets its own surface color
 *  and heavier label so a distressed user can find it without reading. */
export function CrisisHelpButton({ onPress, label = t("buttons.needHelp") }: PressableProps & { label?: string }) {
  const t = useTheme();
  return (
    <TouchableOpacity
      style={[styles.help, { backgroundColor: t.colors.helpBg, borderRadius: t.radius.md, minHeight: t.minTouch }]}
      onPress={onPress}
      accessibilityRole="button"
      accessibilityLabel={label}
      hitSlop={t.touchSlop}
    >
      <Text style={[styles.helpText, { color: t.colors.text, fontSize: 14 }]}>{label}</Text>
    </TouchableOpacity>
  );
}

const styles = StyleSheet.create({
  primary: { borderRadius: 10, padding: 16, alignItems: "center", justifyContent: "center" },
  dimmed: { opacity: 0.6 },
  primaryText: { fontWeight: "600" },
  ghost: { padding: 12 },
  centered: { alignItems: "center" },
  help: { padding: 16, alignItems: "center", justifyContent: "center" },
  helpText: { fontWeight: "700" },
});
