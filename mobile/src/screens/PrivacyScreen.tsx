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

const SECTIONS: readonly { title: string; body: string }[] = [
  {
    title: "What is encrypted",
    body: "Everything you write. Your password derives the encryption keys on this device, and entries are encrypted before they leave it. The server stores only ciphertext. There is no password reset. If you forget your password, no one — including us — can recover your journal.",
  },
  {
    title: "What the server sees",
    body: "Your username, the calendar dates you wrote on, when each entry arrived, and how large each encrypted entry is. A leak of the server's database reveals when and how much you wrote — never what.",
  },
  {
    title: "The one exception: pattern analysis",
    body: "Patterns are computed by the server, which needs your entries decrypted once to do it. When you start an analysis yourself, your key is sent once over an encrypted connection, held in memory for up to 5 minutes, used, and destroyed. It is never stored, and it is never sent for any other reason.",
  },
  {
    title: "Optional AI analysis",
    body: "Off by default for every account. If you turn it on, your decrypted entries are sent to a third-party AI provider chosen by the server operator, and that provider's data-retention policy applies. Turning it on asks for your password, so a borrowed phone cannot change it.",
  },
  {
    title: "Deleting your data",
    body: "Deleting your account removes your entries, patterns, and account from the live database. Database backups and server logs expire on the operator's own schedule — deletion cannot reach back into them. An exported bundle includes everything and stays yours to keep or delete.",
  },
];

export function PrivacyScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  return (
    <ScrollView
      style={[styles.container, { backgroundColor: t.colors.bg }]}
      contentContainerStyle={{ padding: t.spacing.xl, gap: 14 }}
    >
      <Text style={[styles.headline, { color: t.colors.text }]}>Privacy, in plain language</Text>
      {SECTIONS.map((section) => (
        <View key={section.title} style={{ gap: 6 }}>
          <Text style={[styles.sectionTitle, { color: t.colors.accent }]}>{section.title}</Text>
          <Text style={[styles.body, { color: t.colors.body }]}>{section.body}</Text>
        </View>
      ))}
      <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize, lineHeight: 17 }}>
        This policy lives inside the app — reading it needs no connection and leaves no trace anywhere.
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
