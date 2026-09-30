/**
 * Error boundaries (deep audit 2026-09-29, HIGH): before this, ANY uncaught
 * render exception unmounted the whole SPA — a white screen mid-journal,
 * the worst possible failure mode for a distressed user, and the draft
 * seal (`preserveActiveDraft`) only ever ran on lock paths, never on
 * crashes. Two layers:
 *
 *  - `<ErrorBoundary>` (main.tsx): the last resort. Full-page calm copy.
 *  - `<ViewBoundary>` (App.tsx, keyed by view): a crash inside ONE view
 *    falls back to a calm panel while the app frame, navigation and the
 *    crisis overlay stay alive — the user keeps every way out.
 *
 * Both seal the active entry draft before showing the fallback: the words
 * on screen must never be eaten by a rendering bug. The seal is
 * fire-and-forget with a swallow — it must never turn a UI crash into a
 * dropped draft.
 */
import { Component, type ReactNode } from "react";
import { Button, Card, Note } from "./ui";
import { preserveActiveDraft } from "./entryDraft";
import { t } from "./strings";

function sealDraft(): void {
  void preserveActiveDraft().catch(() => undefined);
}

/** Shared fallback body: calm copy, one action, no error text. */
function CrashPanel({ onRetry, retryLabel }: { onRetry: () => void; retryLabel: string }) {
  return (
    <Card title={t("app.crashTitle")}>
      <Note>{t("app.crashBody")}</Note>
      <div className="row row--wrap" style={{ marginTop: "var(--space-3)" }}>
        <Button onPress={onRetry} label={retryLabel} />
      </div>
    </Card>
  );
}

interface BoundaryState {
  failed: boolean;
}

/** Top-level boundary: the page itself stays honest instead of white. */
export class ErrorBoundary extends Component<{ children: ReactNode }, BoundaryState> {
  state: BoundaryState = { failed: false };

  static getDerivedStateFromError(): BoundaryState {
    return { failed: true };
  }

  componentDidCatch(): void {
    sealDraft();
  }

  render(): ReactNode {
    if (this.state.failed) {
      return (
        <main className="app app--login" style={{ maxWidth: 560, margin: "10vh auto", padding: "0 var(--space-4)" }}>
          <CrashPanel onRetry={() => window.location.reload()} retryLabel={t("app.crashReload")} />
        </main>
      );
    }
    return this.props.children;
  }
}

/** Per-view boundary: reset by `resetKey` (the view kind), so navigating
 *  away from a crashed view lands on a working one without a reload. */
export class ViewBoundary extends Component<
  { children: ReactNode; resetKey: string },
  BoundaryState
> {
  state: BoundaryState = { failed: false };

  static getDerivedStateFromError(): BoundaryState {
    return { failed: true };
  }

  componentDidCatch(): void {
    sealDraft();
  }

  componentDidUpdate(prev: { resetKey: string }): void {
    if (prev.resetKey !== this.props.resetKey && this.state.failed) {
      this.setState({ failed: false });
    }
  }

  render(): ReactNode {
    if (this.state.failed) {
      return (
        <CrashPanel onRetry={() => this.setState({ failed: false })} retryLabel={t("app.crashRetry")} />
      );
    }
    return this.props.children;
  }
}
