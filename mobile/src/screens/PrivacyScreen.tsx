/**
 * The privacy policy, in plain language, offline. Static content — like the
 * crisis screen it needs no network, no vault, and no account. Every
 * sentence mirrors the security model in the repository README; when the
 * model changes, both change together.
 */
import React from "react";
import { ScrollView, StyleSheet, Text, View } from "react-native";
import { useTheme } from "../theme";
import { CrisisHelpButton } from "../components/buttons";
import { t as tr } from "../strings";

// Resolved at module load — the app locale is resolved once at startup, so
// the policy cannot switch languages mid-session.
// 2026-09-26 audit (i18n guard): startup-fixed locale — this module-load
// tr() table MUST be revisited if runtime language switching ever ships.
const SECTIONS: readonly { title: string; body: string }[] = [
  {
    title: tr("privacy.s1Title"),
    body: tr("privacy.s1Body"),
  },
  {
    title: tr("privacy.s2Title"),
    body: tr("privacy.s2Body"),
  },
  {
    title: tr("privacy.s3Title"),
    body: tr("privacy.s3Body"),
  },
  {
    title: tr("privacy.s4Title"),
    body: tr("privacy.s4Body"),
  },
  {
    title: tr("privacy.s5Title"),
    body: tr("privacy.s5Body"),
  },
];

export function PrivacyScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  return (
    <ScrollView
      style={[styles.container, { backgroundColor: t.colors.bg }]}
      contentContainerStyle={{ padding: t.spacing.xl, gap: 14 }}
    >
      <Text style={[styles.headline, { color: t.colors.text }]}>{tr("privacy.headline")}</Text>
      {SECTIONS.map((section) => (
        <View key={section.title} style={{ gap: 6 }}>
          <Text style={[styles.sectionTitle, { color: t.colors.accent }]}>{section.title}</Text>
          <Text style={[styles.body, { color: t.colors.body }]}>{section.body}</Text>
        </View>
      ))}
      <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize, lineHeight: 17 }}>
        {tr("privacy.footnote")}
      </Text>
      <CrisisHelpButton onPress={() => navigation.navigate("Crisis")} />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  headline: { fontSize: 22, fontWeight: "700", lineHeight: 29 },
  sectionTitle: { fontSize: 12, fontWeight: "700", letterSpacing: 1.5, textTransform: "uppercase" },
  body: { fontSize: 15, lineHeight: 22 },
});
