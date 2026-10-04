/**
 * Localized crisis resources in an accessible, focus-trapped dialog.
 *
 * Resources are static and available without the API or an unlocked session.
 * Phone numbers, short codes, and URLs are never translated. An unlocked
 * session may also open the local safety plan; that link never gates access
 * to the static resources.
 */
import { t } from "./strings";
import { Button, Dialog, Icon, Note } from "./ui";
import { vault } from "./vault";

/** Large tappable action for a hotline (tel:/sms:) or an external site. */
function CrisisAction(props: { href: string; label: string; detail: string; external?: boolean }): React.JSX.Element {
  return (
    <a
      href={props.href}
      {...(props.external ? { target: "_blank", rel: "noreferrer" } : {})}
      className="btn"
      style={{ justifyContent: "flex-start", textDecoration: "none" }}
    >
      <Icon name={props.external ? "search" : "phone"} size={17} />
      <span className="stack" style={{ gap: 0, textAlign: "left" }}>
        <span>{props.label}</span>
        <span style={{ fontSize: 12, fontWeight: 600, opacity: 0.85 }}>{props.detail}</span>
      </span>
    </a>
  );
}

/** RFC 5724 wants `?body=`; only legacy iOS Safari honors `&body=` (the
 *  same split the mobile app makes in CrisisScreen.tsx). Getting this
 *  wrong on Android silently DROPS the "HOME" keyword that routes the
 *  Crisis Text Line conversation — audit 2026-09-26, fix 2026-09-26 (ii).
 *
 *  Detection is a feature probe now, not a userAgent regex (audit
 *  2026-09-26 LOW): construct the URL and ask the platform's own query
 *  parsing whether the body parameter survived. `?body=` first (the
 *  standard every modern browser implements); anything whose parser
 *  cannot see it falls back to the legacy `&body=` shape. Either way the
 *  HOME keyword stays addressable on both iOS shapes. */
export function smsBodySeparator(bodyIsQueryable: (candidate: string) => boolean): "?" | "&" {
  return bodyIsQueryable("sms:741741?body=HOME") ? "?" : "&";
}

export function crisisSmsLink(): string {
  const bodyIsQueryable = (candidate: string): boolean => {
    try {
      return new URL(candidate).searchParams.get("body") !== null;
    } catch {
      return false;
    }
  };
  return `sms:741741${smsBodySeparator(bodyIsQueryable)}body=HOME`;
}

/** The 988 chat action's destination — the Lifeline's own web chat. The
 *  URL is SAFETY-CRITICAL copy (never translated, never rewritten): a
 *  person who cannot or will not use a phone needs the same lifeline,
 *  in writing. */
export const CRISIS_CHAT_URL = "https://988lifeline.org/chat";

export function CrisisCard(props: { onClose: () => void; onMakeSafetyPlan?: () => void }): React.JSX.Element {
  // The safety-plan link is a SUPPLEMENT, never a gate: it renders only
  // when the vault is unlocked (the plan is data-key-encrypted, so a
  // locked session has nothing to open) and always BELOW the static
  // crisis resources — the numbers and lines above must stay first,
  // complete, and reachable in every state.
  const canOpenPlan = vault.isUnlocked() && props.onMakeSafetyPlan !== undefined;
  return (
    <Dialog title={t("crisis.webTitle")} onClose={props.onClose}>
      <Note tone="danger">{t("crisis.webImmediate")}</Note>
      <div className="stack" style={{ gap: "var(--space-2)" }}>
        <CrisisAction href="tel:911" label={t("crisis.emergency.us")} detail={t("crisis.emergency.detail")} />
        <CrisisAction href="tel:988" label={t("crisis.call988")} detail={t("crisis.call988.detail")} />
        <CrisisAction href={crisisSmsLink()} label={t("crisis.text741741")} detail={t("crisis.text741741.detail")} />
        <CrisisAction href={CRISIS_CHAT_URL} label={t("crisis.chat")} detail={t("crisis.chat.detail")} external />
        <CrisisAction href="https://findahelpline.com" label={t("crisis.findhelpline")} detail={t("crisis.webOutsideUS")} external />
      </div>
      {canOpenPlan && (
        <div className="stack" style={{ gap: "var(--space-2)" }}>
          <Button label={t("crisis.makePlan")} onPress={props.onMakeSafetyPlan!} small variant="ghost" icon="heart" />
          <Note tone="muted">{t("crisis.makePlanNote")}</Note>
        </div>
      )}
      <Note tone="muted">{t("crisis.webSafeMessaging")}</Note>
      <Note tone="muted">{t("crisis.webYouDeserve")}</Note>
      <div className="dialog__actions">
        <Button label={t("common.close")} onPress={props.onClose} small variant="ghost" />
      </div>
    </Dialog>
  );
}
