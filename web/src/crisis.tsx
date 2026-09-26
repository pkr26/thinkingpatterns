/**
 * Crisis resources — one interaction from every screen, reachable in
 * every app state, and STATIC: it must never depend on the API being up
 * or on keys being unlocked (WEB_PLAN P1 skeleton; P8 expands with
 * localization and the full safe-messaging framing).
 *
 * Redesign 2026-09-26: the resources now render in an accessible overlay
 * dialog (role=dialog, focus-trapped, Esc to close) instead of REPLACING
 * the current view — the user's place in the app survives opening help,
 * and closing returns exactly where they were. SAFETY-CRITICAL invariants
 * unchanged: the copy resolves through the t() catalog (a Spanish device
 * reads Spanish support copy) and phone numbers, short codes and URLs
 * (911, 988, 741741, findahelpline.com) are NEVER translated.
 */
import { t } from "./strings";
import { Button, Dialog, Icon, Note } from "./ui";

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
 *  Crisis Text Line conversation — audit 2026-09-26, fix 2026-09-26 (ii). */
export function crisisSmsLink(): string {
  const legacyIos = typeof navigator !== "undefined" && /iPhone|iPad|iPod/i.test(navigator.userAgent);
  return `sms:741741${legacyIos ? "&" : "?"}body=HOME`;
}

export function CrisisCard(props: { onClose: () => void }): React.JSX.Element {
  return (
    <Dialog title={t("crisis.webTitle")} onClose={props.onClose}>
      <Note tone="danger">{t("crisis.webImmediate")}</Note>
      <div className="stack" style={{ gap: "var(--space-2)" }}>
        <CrisisAction href="tel:988" label={t("crisis.call988")} detail={t("crisis.call988.detail")} />
        <CrisisAction href={crisisSmsLink()} label={t("crisis.text741741")} detail={t("crisis.text741741.detail")} />
        <CrisisAction href="https://findahelpline.com" label={t("crisis.findhelpline")} detail={t("crisis.webOutsideUS")} external />
      </div>
      <Note tone="muted">{t("crisis.webSafeMessaging")}</Note>
      <Note tone="muted">{t("crisis.webYouDeserve")}</Note>
      <div className="dialog__actions">
        <Button label={t("common.close")} onPress={props.onClose} small variant="ghost" />
      </div>
    </Dialog>
  );
}
