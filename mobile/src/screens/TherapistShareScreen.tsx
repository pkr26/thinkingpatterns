/**
 * Share with my therapist — the patient side of the zero-knowledge sharing
 * flow (see backend/app/api/consents.py for the server contract).
 *
 * Flow: the therapist's portal shows a short-lived pairing code; the
 * patient types it here. Lookup answers with the therapist's NAME and
 * public key — nothing is shared yet. Only after the disclosure below and
 * a password re-authentication does the app wrap its data key to that
 * therapist's public key (crypto/sharing.ts) and grant. The data key
 * leaves the device exactly once, inside that wrap.
 *
 * Revoking is symmetric: password re-auth, then the server drops the
 * wrapped key — future access dies instantly. The disclosure is honest
 * that already-read data cannot be unread.
 */
import React, { useCallback, useEffect, useState } from "react";
import { Alert, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import { api, ApiError, type ListedConsent, type PairingLookup } from "../api/client";
import { vault } from "../vault";
import { verifyPasswordForVault, isVerificationFailedError, isSessionExpiredError } from "../reauth";
import { therapistKeyFingerprint, wrapDataKeyForTherapist } from "../crypto/sharing";
import { useTheme } from "../theme";
import { PrimaryButton, GhostButton, CrisisHelpButton } from "../components/buttons";
import { calmFallbackCopy } from "../components/errors";
import { t as tr } from "../strings";

type PendingAction =
  | { kind: "grant"; code: string; lookup: PairingLookup }
  | { kind: "revoke"; consentId: string }
  | null;

/**
 * The sharing-disclosure version THIS app renders (audit M-25 / H-14,
 * 2026-09-20): "v2" copy names journal entries, patterns/insights, the
 * wellbeing measures (PHQ-9 questionnaires, readable since 2026-09-19) and
 * the caseload summaries. The server echoes its own current version in
 * GET /meta (sharing_disclosure_version) and rejects a grant whose reviewed
 * disclosure is stale with 409 disclosure_outdated — the screen compares
 * the two BEFORE offering the grant card, so the person never spends a
 * password proof and a key wrap on a consent that cannot land.
 *
 * NOTE (resolved 2026-09-20): both sides now pin "v2" (client.ts
 * SHARING_DISCLOSURE_VERSION, server consents.py), and the sanitized
 * code allowlist carries disclosure_outdated — the 409 branch below is
 * belt-and-braces for a server that moves first.
 */
const SHARING_DISCLOSURE_VERSION_V2 = "v2";

/** True when the 409 is specifically the disclosure gate. The sanitized
 *  code allowlist in client.ts carries disclosure_outdated (audit H-14);
 *  the detail-string fallback stays as belt-and-braces for older builds. */
function isDisclosureOutdated(err: unknown): boolean {
  if (!(err instanceof ApiError) || err.status !== 409) return false;
  if ((err.code as string | undefined) === "disclosure_outdated") return true;
  return typeof err.message === "string" && err.message.toLowerCase().includes("disclosure");
}

const dayOf = (iso: string): string => iso.slice(0, 10);

export function TherapistShareScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const [consents, setConsents] = useState<ListedConsent[]>([]);
  /** L-66: a FAILED consents load is "unknown", not "not sharing" — this
   *  screen is where a revoke gets verified, so the empty-state copy must
   *  only ever follow a successful empty answer. */
  const [consentsFailed, setConsentsFailed] = useState(false);
  const [code, setCode] = useState("");
  const [lookup, setLookup] = useState<PairingLookup | null>(null);
  const [pending, setPending] = useState<PendingAction>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  /** Unknown is rendered as unavailable until the server explicitly opts in;
   * that prevents an old/misconfigured server from presenting a pairing flow
   * which will only fail later with a confusing 404/403. */
  const [sharingAvailable, setSharingAvailable] = useState<boolean | null>(null);
  /** M-25: the server's disclosure version differs from the one this app's
   * copy represents. No new grant is offered while true; existing consents
   * and revoking stay fully available. */
  const [disclosureStale, setDisclosureStale] = useState(false);

  const refresh = useCallback(() => {
    api.meta()
      .then((meta) => {
        const enabled = meta?.sharing_available === true;
        setSharingAvailable(enabled);
        // Only a server that has sharing enabled reports a disclosure
        // version; absent (legacy server / disabled) never counts as stale.
        const serverVersion = (meta as { sharing_disclosure_version?: unknown } | undefined)
          ?.sharing_disclosure_version;
        setDisclosureStale(enabled && typeof serverVersion === "string" && serverVersion !== SHARING_DISCLOSURE_VERSION_V2);
        if (enabled) {
          api.listConsents()
            .then((list) => {
              setConsents(list);
              setConsentsFailed(false);
            })
            .catch(() => {
              setConsents([]);
              setConsentsFailed(true);
            });
        } else {
          setConsents([]);
          setConsentsFailed(false);
        }
      })
      .catch(() => {
        // Unreachable is UNKNOWN, not a server policy decision: null keeps
        // the two situations distinct in the copy (and sends nothing).
        setSharingAvailable(null);
        setConsents([]);
        setConsentsFailed(false);
      });
  }, []);
  useEffect(refresh, [refresh]);

  const findTherapist = async () => {
    if (busy || sharingAvailable !== true || !code.trim()) return;
    setBusy(true);
    try {
      const found = await api.pairingLookup(code.trim());
      setLookup(found);
    } catch (err) {
      if (isSessionExpiredError(err)) {
        Alert.alert(tr("common.sessionExpiredTitle"), tr("common.unlockAgainBody"));
      } else if (err instanceof ApiError && err.status === 404) {
        Alert.alert(tr("share.codeNotFoundTitle"), tr("share.codeNotFoundBody"));
      } else {
        // Offline and server errors are NOT "wrong code": blaming the code
        // (or the therapist) for a dead connection erodes trust.
        Alert.alert(tr("share.lookupFailedTitle"), calmFallbackCopy(err, tr("errors.generic")));
      }
    } finally {
      setBusy(false);
    }
  };

  const confirmGrant = () => {
    if (!lookup) return;
    // L-5 (2026-09-20): the key fingerprint rides the CONFIRMATION too —
    // it used to appear only on the lookup card, so the one dialog that
    // matters for the out-of-band check never repeated it.
    Alert.alert(
      tr("share.grantTitle", { name: lookup.display_name }),
      `${tr("share.grantBody")}\n\n${tr("share.fingerprintNote", {
        fingerprint: therapistKeyFingerprint(lookup.wrap_pub_key),
      })}`,
      [
        { text: tr("common.cancel"), style: "cancel" },
        {
          text: tr("settings.continueToPassword"),
          style: "destructive",
          onPress: () => setPending({ kind: "grant", code: code.trim(), lookup }),
        },
      ],
    );
  };

  const askRevoke = (consent: ListedConsent) => {
    if (busy) return;
    Alert.alert(tr("share.revokeTitle", { name: consent.display_name }), tr("share.revokeBody"), [
      { text: tr("common.cancel"), style: "cancel" },
      {
        text: tr("share.stopSharing"),
        style: "destructive",
        onPress: () => setPending({ kind: "revoke", consentId: consent.id }),
      },
    ]);
  };

  /** Both flows land here: the action only runs after the typed password
   *  re-derives the vault's own auth key (the reauth.ts contract). */
  const confirmWithPassword = async () => {
    if (!pending || busy || !password) return;
    setBusy(true);
    const done = () => { setBusy(false); setPending(null); setPassword(""); setLookup(null); setCode(""); };
    const retry = () => { setBusy(false); setPassword(""); };
    try {
      const reauth = await verifyPasswordForVault(password);
      if (!reauth.ok) {
        const messages = {
          locked: tr("common.reauthLocked"),
          "no-account": tr("common.reauthNoAccount"),
          "wrong-password": tr("common.wrongPassword"),
          offline: tr("common.reauthOffline"),
        } as const;
        Alert.alert(tr("common.couldNotVerifyTitle"), messages[reauth.reason]);
        retry();
        return;
      }
      if (pending.kind === "grant") {
        const userId = await api.getUserId();
        if (!userId) throw new Error(tr("share.noAccount"));
        // The data key leaves the device exactly once: inside this wrap.
        const wrap = wrapDataKeyForTherapist(
          vault.get().dataKey,
          pending.lookup.wrap_pub_key,
          userId,
          pending.lookup.therapist_id,
        );
        await api.grantConsent(pending.code, wrap.ephemeralPubB64, wrap.wrappedKeyB64, reauth.verifierB64);
        Alert.alert(
          tr("share.grantDoneTitle"),
          tr("share.grantDoneBody", { name: pending.lookup.display_name }),
        );
      } else {
        await api.revokeConsent(pending.consentId, reauth.verifierB64);
        Alert.alert(tr("share.revokeDoneTitle"), tr("share.revokeDoneBody"));
      }
      refresh();
      done();
    } catch (err) {
      if (isDisclosureOutdated(err)) {
        // M-25: the server refused the grant because the disclosure this
        // screen reviewed is no longer current (409 disclosure_outdated).
        // The password was RIGHT and nothing was shared — dedicated calm
        // copy instead of a generic conflict or a wrong-password dead end.
        Alert.alert(tr("share.grantOutdatedTitle"), tr("share.grantOutdatedBody"));
        // Re-check the meta version so the stale-state card explains the
        // situation from here on instead of offering another doomed grant.
        refresh();
        done();
        return;
      }
      if (isVerificationFailedError(err)) {
        Alert.alert(tr("common.passwordMismatchTitle"), tr("common.passwordMismatchBody"));
        retry();
        return;
      }
      if (isSessionExpiredError(err)) {
        Alert.alert(tr("common.sessionExpiredTitle"), tr("common.unlockAgainBody"));
      } else {
        Alert.alert(tr("common.couldNotCompleteTitle"), calmFallbackCopy(err, tr("errors.generic")));
      }
      done();
    }
  };

  const themed = {
    label: { color: t.colors.muted, fontSize: 12, fontWeight: "700" as const, letterSpacing: 1, marginTop: 8 },
    input: {
      backgroundColor: t.colors.card,
      color: t.colors.text,
      borderRadius: t.radius.md,
      padding: 14,
      fontSize: 15,
    },
    rowText: { color: t.colors.body, fontSize: 13, flex: 1, lineHeight: 18 },
    footnote: { color: t.colors.muted, fontSize: 12, lineHeight: 18 },
  };

  return (
    <ScrollView
      style={[styles.container, { backgroundColor: t.colors.bg, padding: t.spacing.xxl, gap: 14 }]}
      contentContainerStyle={{ paddingBottom: t.spacing.xxxl }}
    >
      <CrisisHelpButton onPress={() => navigation.navigate("Crisis")} />

      {sharingAvailable === false && (
        <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]} accessibilityRole="alert">
          <Text style={[styles.cardTitle, { color: t.colors.text }]}>{tr("share.unavailableTitle")}</Text>
          <Text style={themed.footnote}>{tr("share.unavailableBody")}</Text>
          <GhostButton label={tr("common.back")} center={false} onPress={() => navigation.goBack?.()} />
        </View>
      )}

      {sharingAvailable === null && (
        <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]} accessibilityRole="alert">
          <Text style={[styles.cardTitle, { color: t.colors.text }]}>{tr("share.unreachableTitle")}</Text>
          <Text style={themed.footnote}>{tr("share.unreachableBody")}</Text>
          <GhostButton label={tr("common.back")} center={false} onPress={() => navigation.goBack?.()} />
        </View>
      )}

      {sharingAvailable === true && <Text style={themed.label}>{tr("share.sharingNowLabel")}</Text>}
      {sharingAvailable === true && consents.length === 0 && !consentsFailed && (
        <Text style={themed.footnote}>{tr("share.notSharingNote")}</Text>
      )}
      {/* L-66: unknown status is never dressed up as the verified empty
          state — the note says the list could not be loaded. */}
      {sharingAvailable === true && consentsFailed && (
        <Text style={themed.footnote}>{tr("share.listFailedNote")}</Text>
      )}
      {sharingAvailable === true && consents.map((consent) => (
        <View
          key={consent.id}
          style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]}
        >
          <Text style={themed.rowText}>
            {consent.display_name}{"\n"}
            <Text style={themed.footnote}>
              {consent.status === "active"
                ? tr("share.sharingSince", { date: dayOf(consent.granted_at) })
                : tr("share.stoppedOn", { date: consent.revoked_at ? dayOf(consent.revoked_at) : "" })}
            </Text>
          </Text>
          {consent.status === "active" && (
            <GhostButton
              label={tr("share.stopSharing")}
              center={false}
              disabled={busy}
              onPress={() => askRevoke(consent)}
            />
          )}
        </View>
      ))}

      {/* M-25: the server's sharing-disclosure version differs from the one
          this app's copy represents — show the calm "terms updated" state
          instead of a grant card that can only 409 after a password proof
          and a key wrap. Existing sharing stays visible and revocable. */}
      {sharingAvailable === true && disclosureStale && (
        <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]} accessibilityRole="alert">
          <Text style={[styles.cardTitle, { color: t.colors.text }]}>{tr("share.termsUpdatedTitle")}</Text>
          <Text style={themed.footnote}>{tr("share.termsUpdatedBody")}</Text>
        </View>
      )}

      {sharingAvailable === true && !disclosureStale && !lookup && (
        <>
          <Text style={themed.label}>{tr("share.addLabel")}</Text>
          <Text style={themed.footnote}>{tr("share.addBody")}</Text>
          <TextInput
            style={themed.input}
            value={code}
            onChangeText={setCode}
            autoCapitalize="characters"
            placeholder={tr("share.codePlaceholder")}
            placeholderTextColor={t.colors.placeholder}
            accessibilityLabel={tr("share.codeA11y")}
          />
          <PrimaryButton
            label={busy ? tr("share.lookingUp") : tr("share.findTherapist")}
            onPress={findTherapist}
            disabled={busy || !code.trim()}
          />
        </>
      )}

      {sharingAvailable === true && lookup && !pending && (
        <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]}>
          <Text style={[styles.cardTitle, { color: t.colors.text }]}>{lookup.display_name}</Text>
          <Text style={themed.footnote}>
            {tr("share.fingerprintNote", { fingerprint: therapistKeyFingerprint(lookup.wrap_pub_key) })}
          </Text>
          <Text style={themed.footnote}>{tr("share.disclosure")}</Text>
          <PrimaryButton
            label={tr("share.shareWithName", { name: lookup.display_name })}
            onPress={confirmGrant}
            disabled={busy}
          />
          <GhostButton
            label={tr("common.cancel")}
            disabled={busy}
            onPress={() => { setLookup(null); setCode(""); }}
          />
        </View>
      )}

      {sharingAvailable === true && pending && (
        <View style={[styles.reauthCard, { backgroundColor: t.colors.cardDeep, borderRadius: t.radius.lg }]}>
          <Text style={[styles.reauthTitle, { color: t.colors.text }]}>
            {pending.kind === "grant"
              ? tr("share.reauthGrantTitle", { name: pending.lookup.display_name })
              : tr("share.reauthRevokeTitle")}
          </Text>
          <TextInput
            style={themed.input}
            placeholder={tr("common.passwordPlaceholder")}
            placeholderTextColor={t.colors.placeholder}
            secureTextEntry
            value={password}
            onChangeText={setPassword}
            accessibilityLabel={tr("common.passwordConfirmA11y")}
            textContentType="password"
          />
          <PrimaryButton
            label={busy ? tr("common.verifying") : tr("common.confirmWithPassword")}
            onPress={confirmWithPassword}
            disabled={!password}
            danger={pending.kind === "revoke"}
            accessibilityLabel={tr("common.confirmWithPassword")}
          />
          <GhostButton
            label={tr("common.cancel")}
            disabled={busy}
            onPress={() => { setPending(null); setPassword(""); }}
          />
        </View>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  card: { padding: 16, gap: 8 },
  cardTitle: { fontSize: 15, fontWeight: "600" },
  reauthCard: { padding: 16, gap: 12 },
  reauthTitle: { fontSize: 15, fontWeight: "600", lineHeight: 20 },
});
