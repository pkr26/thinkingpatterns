/**
 * Accessible patient-facing UI components styled by public/app.css.
 *
 * Disabled buttons omit their handlers; cards use section headings; controls
 * have associated labels; notices expose live regions. Selection uses the
 * primary palette rather than the danger color. Charts use tokens.ts to
 * stay synchronized with the light and dark CSS themes.
 */
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { t } from "./strings";
import { moodFaceColors, usePaletteVersion } from "./tokens";

/* ------------------------------------------------------------------ icons
   A tiny hand-rolled stroke icon set (no icon dependency). Decorative by
   contract: aria-hidden, and every control carrying one also carries a
   text/aria label. */
export type IconName =
  | "home" | "book" | "sparkles" | "help" | "clipboard" | "share" | "sliders"
  | "shield" | "flame" | "sun" | "moon" | "chevron-left" | "chevron-right"
  | "chevron-down" | "check" | "x" | "heart" | "alert" | "info" | "copy"
  | "more" | "logout" | "edit" | "trash" | "search" | "refresh" | "phone"
  | "mic" | "play";

const ICON_PATHS: Record<IconName, ReactNode> = {
  home: <><path d="M3 11.5 12 4l9 7.5" /><path d="M5.5 10v10h13V10" /></>,
  book: <><path d="M6.5 3H18a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H6.5A2.5 2.5 0 0 1 4 18.5v-13A2.5 2.5 0 0 1 6.5 3z" /><path d="M8 3v18" /><path d="M11.5 8.5h4" /></>,
  sparkles: <><path d="M12 3l1.7 4.6L18.3 9l-4.6 1.4L12 15l-1.7-4.6L5.7 9l4.6-1.4L12 3z" /><path d="M18.5 15l.8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8.8-2.2z" /></>,
  help: <><circle cx="12" cy="12" r="9" /><path d="M9.6 9.6a2.4 2.4 0 1 1 3.3 2.2c-.8.34-1.3.95-1.3 1.9" /><path d="M11.6 16.6v.1" /></>,
  clipboard: <><path d="M9 4.5H7A1.5 1.5 0 0 0 5.5 6v13A1.5 1.5 0 0 0 7 20.5h10a1.5 1.5 0 0 0 1.5-1.5V6A1.5 1.5 0 0 0 17 4.5h-2" /><rect x="9" y="3" width="6" height="3" rx="1" /></>,
  share: <><circle cx="18" cy="5.5" r="2.4" /><circle cx="6" cy="12" r="2.4" /><circle cx="18" cy="18.5" r="2.4" /><path d="M8.2 10.8l7.6-4.1" /><path d="M8.2 13.2l7.6 4.1" /></>,
  sliders: <><path d="M4 7h7" /><path d="M16.5 7H20" /><circle cx="13.5" cy="7" r="2.2" /><path d="M4 17h3" /><path d="M12.5 17H20" /><circle cx="9.5" cy="17" r="2.2" /></>,
  shield: <><path d="M12 3l7 3v5c0 4.5-3 7.6-7 9.2C8 18.6 5 15.5 5 11V6z" /><path d="M9 11.6l2.1 2.1 4-4.2" /></>,
  flame: <><path d="M12 3c1 3 4.2 4.6 4.2 8.2a4.7 4.7 0 0 1-9.4 0c0-1.6.6-3 1.5-4.2.4 1 1.1 1.6 2 1.8C10.4 7 11.5 5 12 3z" /></>,
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2.5V5" /><path d="M12 19v2.5" /><path d="M2.5 12H5" /><path d="M19 12h2.5" /><path d="M5 5l1.7 1.7" /><path d="M17.3 17.3 19 19" /><path d="M19 5l-1.7 1.7" /><path d="M6.7 17.3 5 19" /></>,
  moon: <path d="M20 13.6A8 8 0 1 1 10.4 4a6.6 6.6 0 0 0 9.6 9.6z" />,
  "chevron-left": <path d="M14.5 5.5 8 12l6.5 6.5" />,
  "chevron-right": <path d="M9.5 5.5 16 12l-6.5 6.5" />,
  "chevron-down": <path d="M6 9.5l6 6 6-6" />,
  check: <path d="M5 12.5l4.5 4.5L19 7.5" />,
  x: <><path d="M6 6l12 12" /><path d="M18 6 6 18" /></>,
  heart: <path d="M12 20s-7-4.3-9-8.5C1.6 8.6 3.6 5.5 6.8 5.5c1.9 0 3.6 1 4.2 2.6.6-1.6 2.3-2.6 4.2-2.6 3.2 0 5.2 3.1 3.8 6-2 4.2-7 8.5-7 8.5z" />,
  alert: <><path d="M12 4 2.8 20h18.4z" /><path d="M12 10v4.2" /><path d="M12 17.4v.1" /></>,
  info: <><circle cx="12" cy="12" r="9" /><path d="M12 11.2V16" /><path d="M12 8.2v.1" /></>,
  copy: <><rect x="9" y="9" width="10.5" height="10.5" rx="2" /><path d="M6.5 15H5.5A1.5 1.5 0 0 1 4 13.5v-8A1.5 1.5 0 0 1 5.5 4h8A1.5 1.5 0 0 1 15 5.5v1" /></>,
  more: <><circle cx="5" cy="12" r="1.6" fill="currentColor" stroke="none" /><circle cx="12" cy="12" r="1.6" fill="currentColor" stroke="none" /><circle cx="19" cy="12" r="1.6" fill="currentColor" stroke="none" /></>,
  logout: <><path d="M9.5 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h3.5" /><path d="M15.5 8l4 4-4 4" /><path d="M19.5 12h-10" /></>,
  edit: <><path d="M4 20h4.5L20 8.5a2.12 2.12 0 0 0-3-3L5.5 17 4 20z" /><path d="M14.5 7l3 3" /></>,
  trash: <><path d="M4.5 7h15" /><path d="M9.5 7V4.5h5V7" /><path d="M7 7l1 13h8l1-13" /><path d="M10.3 10.5v6" /><path d="M13.7 10.5v6" /></>,
  search: <><circle cx="11" cy="11" r="6.5" /><path d="M15.8 15.8 21 21" /></>,
  refresh: <><path d="M20 12a8 8 0 1 1-2.34-5.66" /><path d="M20 4v4.5h-4.5" /></>,
  phone: <path d="M6 3.5h3l1.5 4-2 1.5a11.5 11.5 0 0 0 5 5l1.5-2 4 1.5v3a2 2 0 0 1-2 2A14 14 0 0 1 4 5.5a2 2 0 0 1 2-2z" />,
  mic: <><rect x="9" y="3" width="6" height="11" rx="3" /><path d="M5.5 11.5a6.5 6.5 0 0 0 13 0" /><path d="M12 18v3" /></>,
  play: <><circle cx="12" cy="12" r="9" /><path d="M10 8.5l6 3.5-6 3.5z" /></>,
};

export function Icon(props: { name: IconName; size?: number }): React.JSX.Element {
  return (
    <svg
      width={props.size ?? 18}
      height={props.size ?? 18}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {ICON_PATHS[props.name]}
    </svg>
  );
}

/* ------------------------------------------------------------------ brand
   Abstract bloom mark — soft, non-clinical, no people imagery
   (trauma-informed: decorative shapes only). */
export function Logo({ size = 30 }: { size?: number }): React.JSX.Element {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" focusable="false">
      <circle cx="16" cy="16" r="16" fill="var(--primary-soft)" />
      <path d="M16 24c-5 0-8-3.2-8-8 4.8 0 7.8 3 8 8z" fill="var(--primary)" />
      <path d="M16 24c5 0 8-3.2 8-8-4.8 0-7.8 3-8 8z" fill="var(--primary)" opacity="0.72" />
      <path d="M16 8v16" stroke="var(--primary-strong)" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  );
}

/* ----------------------------------------------------------------- button */
export function Button(props: {
  label: string;
  onPress: () => void;
  disabled?: boolean;
  danger?: boolean;
  small?: boolean;
  variant?: "primary" | "ghost" | "quiet";
  icon?: IconName;
  block?: boolean;
}): React.JSX.Element {
  const classes = ["btn"];
  if (props.danger) classes.push("btn--danger");
  else if (props.variant === "ghost") classes.push("btn--ghost");
  else if (props.variant === "quiet") classes.push("btn--quiet");
  if (props.small) classes.push("btn--small");
  if (props.block) classes.push("btn--block");
  return (
    <button
      type="button"
      // The handler is not merely ignored — it is absent — when disabled,
      // so no synthetic click path can fire it.
      onClick={props.disabled ? undefined : props.onPress}
      disabled={props.disabled === true}
      className={classes.join(" ")}
    >
      {props.icon && <Icon name={props.icon} size={props.small ? 15 : 17} />}
      {props.label}
    </button>
  );
}

/* ------------------------------------------------------------------- chip
   One-tap option button (activity tags, measure answers, feedback).
   Selected = aria-pressed + soft sage fill + check — never danger red.
   `toggle={false}` renders a PLAIN action chip (prompt seeds): those are
   one-shot inserts, not on/off states, so aria-pressed would be a lie. */
export function Chip(props: {
  label: string;
  onPress: () => void;
  selected?: boolean;
  disabled?: boolean;
  icon?: IconName;
  toggle?: boolean;
}): React.JSX.Element {
  const toggle = props.toggle !== false;
  return (
    <button
      type="button"
      onClick={props.disabled ? undefined : props.onPress}
      disabled={props.disabled === true}
      {...(toggle ? { "aria-pressed": props.selected === true } : {})}
      className="chip"
    >
      {props.icon && <Icon name={props.icon} size={15} />}
      {props.label}
      {toggle && <span className="chip__check"><Icon name="check" size={14} /></span>}
    </button>
  );
}

/* ------------------------------------------------------------------- card */
export function Card(props: {
  children: ReactNode;
  deep?: boolean;
  title?: string;
  tone?: "sensitive" | "danger";
}): React.JSX.Element {
  const classes = ["card"];
  if (props.deep) classes.push("card--deep");
  if (props.tone === "sensitive") classes.push("card--sensitive");
  if (props.tone === "danger") classes.push("card--danger");
  return (
    <section className={classes.join(" ")}>
      {props.title && <h2 className="card__title">{props.title}</h2>}
      {props.children}
    </section>
  );
}

/* ------------------------------------------------------------------ forms */
export function Field(props: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  placeholder?: string;
  autoComplete?: string;
}): React.JSX.Element {
  return (
    <label className="field">
      <span className="field__label">{props.label}</span>
      <input
        type={props.type ?? "text"}
        value={props.value}
        placeholder={props.placeholder}
        autoComplete={props.autoComplete}
        onChange={(e) => props.onChange(e.target.value)}
        className="input"
      />
    </label>
  );
}

/** Multi-line journal editor. The label is wrapped like Field's so the
 *  control stays programmatically findable in tests and for a11y. */
export function TextArea(props: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  rows?: number;
  maxLength?: number;
  disabled?: boolean;
}): React.JSX.Element {
  return (
    <label className="field">
      <span className="field__label">{props.label}</span>
      <textarea
        value={props.value}
        placeholder={props.placeholder}
        rows={props.rows ?? 8}
        maxLength={props.maxLength}
        disabled={props.disabled}
        onChange={(e) => props.onChange(e.target.value)}
        className="textarea"
      />
    </label>
  );
}

/* ------------------------------------------------------------------ notes */
export function Note(props: { children: ReactNode; tone?: "muted" | "ok" | "danger" | "warn" | "lead"; role?: "status" }): React.JSX.Element {
  const classes = ["note"];
  if (props.tone && props.tone !== "lead") classes.push(`note--${props.tone}`);
  if (props.tone === "lead") classes.push("note--lead");
  // Journal text and prompts are multi-line by nature; line breaks must
  // survive rendering.
  return <p role={props.role} className={classes.join(" ")} style={{ whiteSpace: "pre-wrap" }}>{props.children}</p>;
}

/** Soft inline status pill (sentiment read, streaks, queue states). */
export function PillNote(props: { children: ReactNode; tone?: "muted" | "ok" | "warn"; icon?: IconName; role?: "status" }): React.JSX.Element {
  const classes = ["pill-note"];
  if (props.tone === "ok") classes.push("pill-note--ok");
  if (props.tone === "warn") classes.push("pill-note--warn");
  return (
    <span role={props.role} className={classes.join(" ")}>
      {props.icon && <Icon name={props.icon} size={14} />}
      {props.children}
    </span>
  );
}

export function ErrorBanner({ message }: { message: string }): React.JSX.Element | null {
  if (!message) return null;
  return (
    <div role="alert" className="banner banner--error">
      {message}
    </div>
  );
}

/* ----------------------------------------------------------------- switch */
export function Toggle(props: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  disabled?: boolean;
}): React.JSX.Element {
  return (
    <div className="row row--between">
      <span className="note" style={{ whiteSpace: "pre-wrap" }}>{props.label}</span>
      <button
        type="button"
        role="switch"
        aria-checked={props.checked}
        aria-label={props.label}
        onClick={props.disabled ? undefined : () => props.onChange(!props.checked)}
        disabled={props.disabled === true}
        className="toggle"
      />
    </div>
  );
}

/* --------------------------------------------------------------- checkbox */
export function Checkbox(props: { checked: boolean; onChange: (checked: boolean) => void; children: ReactNode }): React.JSX.Element {
  return (
    <label className="checkbox">
      <input
        type="checkbox"
        className="checkbox__input"
        checked={props.checked}
        onChange={(e) => props.onChange(e.target.checked)}
      />
      <span className="checkbox__box" aria-hidden="true">
        <span className="checkbox__check"><Icon name="check" size={13} /></span>
      </span>
      <span>{props.children}</span>
    </label>
  );
}

/* ------------------------------------------------------- segmented control
   Radiogroup with the full keyboard pattern: the checked option is the
   tab stop (roving tabindex); Arrow keys/Home/End move and select —
   what role=radiogroup promises (audit 2026-09-26 fix). */
export function SegmentedControl(props: {
  options: { id: string; label: string }[];
  activeId: string;
  onSelect: (id: string) => void;
  a11yLabel: string;
}): React.JSX.Element {
  const optionAt = (index: number): { id: string; label: string } | undefined => props.options[index];
  const onKeyDown = (event: React.KeyboardEvent<HTMLButtonElement>, index: number): void => {
    let next: number | null = null;
    if (event.key === "ArrowRight" || event.key === "ArrowDown") next = (index + 1) % props.options.length;
    else if (event.key === "ArrowLeft" || event.key === "ArrowUp") next = (index - 1 + props.options.length) % props.options.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = props.options.length - 1;
    if (next === null) return;
    event.preventDefault();
    const target = optionAt(next);
    if (!target) return;
    props.onSelect(target.id);
    // Focus follows selection in the radio pattern; the freshly checked
    // option is the new tab stop.
    const buttons = event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>(".segmented__opt");
    buttons?.[next]?.focus();
  };
  return (
    <div className="segmented" role="radiogroup" aria-label={props.a11yLabel}>
      {props.options.map((option, index) => (
        <button
          key={option.id}
          type="button"
          role="radio"
          aria-checked={option.id === props.activeId}
          tabIndex={option.id === props.activeId ? 0 : -1}
          className="segmented__opt"
          onClick={() => props.onSelect(option.id)}
          onKeyDown={(event) => onKeyDown(event, index)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

/* --------------------------------------------------------------- navigation */
export interface NavItem { id: string; label: string; icon: IconName }

export function NavTabs(props: { items: NavItem[]; activeId: string | null; onSelect: (id: string) => void }): React.JSX.Element {
  return (
    <nav className="nav-tabs" aria-label={t("nav.a11y")}>
      {props.items.map((item) => (
        <button
          key={item.id}
          type="button"
          className="nav-tabs__item"
          aria-current={item.id === props.activeId ? "page" : undefined}
          onClick={() => props.onSelect(item.id)}
        >
          <Icon name={item.icon} size={16} />
          {item.label}
        </button>
      ))}
    </nav>
  );
}

export function BottomNav(props: { items: NavItem[]; activeId: string | null; onSelect: (id: string) => void; more: ReactNode }): React.JSX.Element {
  return (
    <nav className="bottom-nav" aria-label={t("nav.a11y")}>
      {props.items.map((item) => (
        <button
          key={item.id}
          type="button"
          className="bottom-nav__item"
          aria-current={item.id === props.activeId ? "page" : undefined}
          onClick={() => props.onSelect(item.id)}
        >
          <Icon name={item.icon} size={21} />
          {item.label}
        </button>
      ))}
      {props.more}
    </nav>
  );
}

export interface MoreMenuItem { id: string; label: string; icon?: IconName; danger?: boolean }

/** Overflow menu (desktop: after the tabs; mobile: above the bottom bar).
 *  Full menu keyboard pattern: opening focuses the first item, arrows/
 *  Home/End roam, Escape/outside closes and returns focus to the trigger
 *  (audit 2026-09-26 fix — role=menu promises arrows). */
export function MoreMenu(props: {
  label: string;
  items: MoreMenuItem[];
  activeIds: readonly string[];
  onSelect: (id: string) => void;
  up?: boolean;
}): React.JSX.Element {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const active = props.activeIds.length > 0;

  useEffect(() => {
    if (!open || typeof document === "undefined") return;
    const onDown = (event: MouseEvent): void => {
      if (root.current && event.target instanceof Node && !root.current.contains(event.target)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === "Escape") {
        setOpen(false);
        trigger.current?.focus();
      }
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    // Opening a menu moves focus INTO it (WAI-ARIA menu pattern).
    root.current?.querySelector<HTMLButtonElement>(".more__item")?.focus();
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const onMenuKeyDown = (event: React.KeyboardEvent<HTMLButtonElement>, index: number): void => {
    let next: number | null = null;
    if (event.key === "ArrowDown") next = (index + 1) % props.items.length;
    else if (event.key === "ArrowUp") next = (index - 1 + props.items.length) % props.items.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = props.items.length - 1;
    else if (event.key === "Tab") {
      // Tab out of the menu closes it (focus leaves by browser default).
      setOpen(false);
      return;
    }
    if (next === null) return;
    event.preventDefault();
    const buttons = root.current?.querySelectorAll<HTMLButtonElement>(".more__item");
    buttons?.[next]?.focus();
  };

  return (
    <div className={`more${props.up ? " more--up" : ""}`} ref={root}>
      <button
        ref={trigger}
        type="button"
        className="nav-tabs__item"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-current={active && !open ? "page" : undefined}
        onClick={() => setOpen(!open)}
      >
        <Icon name="more" size={16} />
        {props.label}
        <Icon name="chevron-down" size={13} />
      </button>
      {open && (
        <div className="more__menu" role="menu" aria-label={props.label}>
          {props.items.map((item, index) => (
            <button
              key={item.id}
              type="button"
              role="menuitem"
              className={`more__item${item.danger ? " more__item--danger" : ""}`}
              aria-current={props.activeIds.includes(item.id) ? "page" : undefined}
              onClick={() => {
                setOpen(false);
                props.onSelect(item.id);
              }}
              onKeyDown={(event) => onMenuKeyDown(event, index)}
            >
              {item.icon && <Icon name={item.icon} size={16} />}
              {item.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/* ----------------------------------------------------------------- dialog
   Accessible modal: role=dialog + aria-modal, focus is trapped while
   open and restored on close, Escape closes, backdrop click closes.
   Effects no-op where the DOM doesn't exist (node test environment).

   Hardening 2026-09-26 (ii): the trap used to re-run on every identity
   change of `onClose` (App passes an inline arrow), which re-stole focus
   mid-dialog and captured "previous" from INSIDE the dialog — close then
   restored focus to body. The close callback now lives in a ref and the
   effect runs exactly once per mount. */
export function Dialog(props: { title: string; onClose: () => void; children: ReactNode }): React.JSX.Element {
  const panel = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(props.onClose);
  useLayoutEffect(() => {
    onCloseRef.current = props.onClose;
  });

  useLayoutEffect(() => {
    if (typeof document === "undefined") return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    // True modality: everything the dialog sits INSIDE of must stay
    // focusable, while its siblings go inert — the dialog itself is a
    // child of #app-content (AppFrame renders it with the view), so the
    // inert set is "children of the app content except the dialog's own
    // subtree" (audit P3, hardening 2026-09-26 ii; the naive
    // inert-on-#app-content variant muted the dialog's own focusables —
    // caught live in E2E and pinned in tests/interaction.test.tsx).
    const appContent = document.getElementById("app-content");
    const panelEl = panel.current;
    const inerted =
      appContent && panelEl
        ? Array.from(appContent.children).filter((el) => !el.contains(panelEl) && !panelEl.contains(el))
        : [];
    inerted.forEach((el) => el.setAttribute("inert", ""));
    const focusables = (): HTMLElement[] => {
      if (!panel.current) return [];
      return Array.from(
        panel.current.querySelectorAll<HTMLElement>("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])"),
      ).filter((el) => !el.hasAttribute("disabled"));
    };
    focusables()[0]?.focus();
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === "Escape") {
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== "Tab") return;
      const list = focusables();
      if (list.length === 0) return;
      const first = list[0]!;
      const last = list[list.length - 1]!;
      const activeInside = panel.current?.contains(document.activeElement) === true;
      if (!activeInside) {
        // Focus escaped the panel (backdrop, an outer re-focus): pull it
        // back to the correct end instead of letting Tab walk the page
        // behind a dialog the user believes is modal.
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
        return;
      }
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      inerted.forEach((el) => el.removeAttribute("inert"));
      previous?.focus();
    };
    // The trap's lifetime is the dialog's lifetime — onClose identity
    // changes must NEVER tear it down (see the comment above).
  }, []);

  return (
    <div
      className="dialog-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) props.onClose();
      }}
    >
      <div ref={panel} role="dialog" aria-modal="true" aria-label={props.title} className="dialog">
        <h2 className="dialog__title">{props.title}</h2>
        {props.children}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ toast */
export interface ToastItem { id: number; message: string; tone: "ok" | "warn" | "info" }

/** The live region stays MOUNTED (empty included): a region that appears
 *  together with its first toast is one some screen-reader combinations
 *  miss announcing (audit 2026-09-26 fix). */
export function ToastHost({ items }: { items: ToastItem[] }): React.JSX.Element {
  return (
    <div className="toast-host" role="status" aria-live="polite">
      {items.map((toast) => (
        <div key={toast.id} className="toast">
          <Icon name={toast.tone === "ok" ? "check" : toast.tone === "warn" ? "alert" : "info"} size={16} />
          {toast.message}
        </div>
      ))}
    </div>
  );
}

/* --------------------------------------------------------------- skeleton */
export function Skeleton(props: { lines?: number; title?: boolean }): React.JSX.Element {
  const lines = props.lines ?? 3;
  return (
    <div aria-hidden="true" className="stack">
      {props.title === true && <div className="skeleton skeleton--title" />}
      {Array.from({ length: lines }, (_, index) => (
        <div key={index} className={`skeleton${index === lines - 1 ? " skeleton--line-short" : " skeleton--line"}`} />
      ))}
    </div>
  );
}

/* --------------------------------------------------------- progress pieces */
export function ProgressDots(props: { total: number; current: number; label: string }): React.JSX.Element {
  return (
    <div className="dots" role="img" aria-label={props.label}>
      {Array.from({ length: props.total }, (_, index) => (
        <span key={index} className={`dots__dot${index === props.current ? " dots__dot--on" : ""}`} />
      ))}
    </div>
  );
}

export function ProgressTrack(props: { progress: number; label: string }): React.JSX.Element {
  const clamped = Math.max(0, Math.min(1, props.progress));
  return (
    <div className="stack">
      <div className="progress-track" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(clamped * 100)} aria-label={props.label}>
        <div className="progress-fill" style={{ width: `${Math.round(clamped * 100)}%` }} />
      </div>
    </div>
  );
}

/* ------------------------------------------------------- check-in controls
   The one-tap visual scales (Daylio-style frictionless check-in). Faces
   carry per-level ring colors AND per-level expressions (brows + mouth
   bend with the level so five side-by-side faces are told apart at a
   glance, not five near-identical circles — audit 2026-09-26 fix);
   selection is aria-pressed + check badge + ring + scale, never a
   color-only cue. Face colors are theme-aware (tokens.moodFaceColors). */
export interface ScaleOption { value: number; labelKey: string }

/** Mouth path for a scale position 0..1 (heaviest → lightest). */
function faceMouth(position: number): string {
  if (position <= 0) return "M8 17.6 Q12 12.8 16 17.6";       // deep frown
  if (position < 0.25) return "M8.3 16.4 Q12 13.8 15.7 16.4"; // slight frown
  if (position < 0.5) return "M8.5 15.4 H15.5";               // level
  if (position < 0.75) return "M8.3 14.4 Q12 17.6 15.7 14.4"; // smile
  return "M7.8 13.9 Q12 18.9 16.2 13.9";                      // broad smile
}

/** Brow pair for the same position: worried ↓↘ for the heavy end, flat
 *  in the middle (a genuinely neutral face), lifted ↗ for the light end.
 *  Bands are discrete-position safe: 0/0.25 → worried, 0.5 → none,
 *  0.75/1 → lifted. */
function faceBrows(position: number): string[] {
  if (position < 0.3) {
    if (position <= 0) return ["M7.2 7.2 L10.1 8.5", "M16.8 7.2 L13.9 8.5"];
    return ["M7.5 7.7 L10.1 8.7", "M16.5 7.7 L13.9 8.7"];
  }
  if (position <= 0.7) return [];
  if (position < 1) return ["M7.5 8.6 L10.1 7.8", "M16.5 8.6 L13.9 7.8"];
  return ["M7.2 8.8 L10.1 7.5", "M16.8 8.8 L13.9 7.5"];
}

export function MoodScale(props: { groupLabel?: string; options: readonly ScaleOption[]; value: number | null; onChange: (value: number | null) => void }): React.JSX.Element {
  // Re-resolve face colors when the theme flips (auto mode included).
  usePaletteVersion();
  const last = props.options.length - 1;
  return (
    <div className="mood-scale" role="group" aria-label={props.groupLabel ?? t("entry.moodQuestion")}>
      {props.options.map((option, index) => {
        const level = last <= 0 ? 2 : Math.round((index * 4) / last);
        const colors = moodFaceColors(level);
        const pressed = props.value === option.value;
        const position = last <= 0 ? 0.5 : index / last;
        return (
          <button
            key={option.labelKey}
            type="button"
            className="mood-item"
            aria-pressed={pressed}
            aria-label={t(option.labelKey)}
            onClick={() => props.onChange(pressed ? null : option.value)}
            style={{ "--face": colors.face, "--face-soft": colors.faceSoft, "--face-strong": colors.faceStrong } as React.CSSProperties}
          >
            <span className="mood-face" aria-hidden="true">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round">
                <circle cx="12" cy="12" r="9.2" />
                <circle cx="8.8" cy="10.2" r="1.2" fill="currentColor" stroke="none" />
                <circle cx="15.2" cy="10.2" r="1.2" fill="currentColor" stroke="none" />
                {faceBrows(position).map((d) => <path key={d} d={d} />)}
                <path d={faceMouth(position)} />
              </svg>
              {pressed && (
                <span className="mood-face__check"><Icon name="check" size={12} /></span>
              )}
            </span>
            <span className="mood-item__label">{t(option.labelKey)}</span>
          </button>
        );
      })}
    </div>
  );
}

/** The 1–5 sleep scale (and any short numeric pick): labeled round dots.
 *  The accessible name is "{n} — {label}" (not the concatenated spans,
 *  which read as "1Rough" — audit 2026-09-26 fix). */
export function DotScale(props: { groupLabel?: string; options: readonly ScaleOption[]; value: number | null; onChange: (value: number | null) => void }): React.JSX.Element {
  return (
    <div className="dot-scale" role="group" aria-label={props.groupLabel ?? t("entry.sleepQuestion")}>
      {props.options.map((option, index) => {
        const pressed = props.value === option.value;
        return (
          <button
            key={option.labelKey}
            type="button"
            className="dot-item"
            aria-pressed={pressed}
            aria-label={`${index + 1} — ${t(option.labelKey)}`}
            onClick={() => props.onChange(pressed ? null : option.value)}
          >
            <span className="dot" aria-hidden="true">{index + 1}</span>
            <span className="dot-item__label">{t(option.labelKey)}</span>
          </button>
        );
      })}
    </div>
  );
}

/** Short qualitative pick rendered as filled energy bars (Drained 1/3 →
 *  Energized 3/3) — energy is NOT a mood, so it stops borrowing smiley
 *  faces (audit 2026-09-26 fix); bars make the direction obvious. */
export function BarScale(props: { options: readonly ScaleOption[]; value: number | null; onChange: (value: number | null) => void; groupLabel: string }): React.JSX.Element {
  return (
    <div className="bar-scale" role="group" aria-label={props.groupLabel}>
      {props.options.map((option, index) => {
        const pressed = props.value === option.value;
        return (
          <button
            key={option.labelKey}
            type="button"
            className="bar-item"
            aria-pressed={pressed}
            aria-label={t(option.labelKey)}
            onClick={() => props.onChange(pressed ? null : option.value)}
          >
            <span className="bar-bars" aria-hidden="true">
              {props.options.map((_, bar) => (
                <span key={bar} className={`bar-bars__cell${bar <= index ? " bar-bars__cell--on" : ""}`} />
              ))}
            </span>
            <span className="bar-item__label">{t(option.labelKey)}</span>
          </button>
        );
      })}
    </div>
  );
}

/* ------------------------------------------------------------------ avatar */
export function Avatar({ name }: { name: string }): React.JSX.Element {
  const initials = name.trim().split(/\s+/).slice(0, 2).map((part) => part.charAt(0).toUpperCase()).join("") || "?";
  return <span className="avatar" aria-hidden="true">{initials}</span>;
}

/* --------------------------------------------------------------- app frame */
/** App chrome: sticky header (brand + the crisis entry point that must be
 *  one interaction from every screen — WEB_PLAN P8.1, present from day
 *  one) and the responsive content column. Safety-visible copy resolves
 *  through t() — never hardcoded English. */
export function AppFrame(props: { title: string; onCrisis: () => void; children: ReactNode }): React.JSX.Element {
  return (
    <>
      {/* The skip link is the first tabbable element; visual users never
          see it until it has focus (keyboard a11y floor, P8.3). */}
      <a href="#app-content" className="skip-link">{t("nav.skipToContent")}</a>
      <header className="app-header">
        <h1 className="brand__name" style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Logo />
          {props.title}
        </h1>
        {/* The crisis entry point stays one tap from every screen. The
            warm amber treatment keeps it calm while making it VISIBLE —
            a safety action should not be the quietest control on the
            screen (audit 2026-09-26 fix; still never danger-red). */}
        <button type="button" className="btn btn--help btn--small" onClick={props.onCrisis}>
          <Icon name="phone" size={15} />
          {t("nav.getHelp")}
        </button>
      </header>
      <main className="app-main" id="app-content">{props.children}</main>
    </>
  );
}
