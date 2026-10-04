/**
 * App-level and view-level render boundaries.
 *
 * The app boundary offers a reload; the view boundary preserves navigation
 * and crisis resources. Both attempt to seal the active journal draft and
 * safety plan. Persistence failures must not prevent the fallback UI.
 */
import { Component, type ReactNode } from "react";
import { Button, Card, Note } from "./ui";
import { preserveActiveDraft } from "./entryDraft";
import { preserveSafetyPlan } from "./safetyPlan";
import { t } from "./strings";

function sealDraft(): void {
  void preserveActiveDraft().catch(() => undefined);
  // 2026-10-01 audit M11: the safety plan survives a crash the same way.
  void preserveSafetyPlan().catch(() => undefined);
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
