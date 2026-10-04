/**
 * App-level and view-level render boundaries for the therapist portal.
 * The app fallback offers a reload; the view fallback preserves the session
 * and navigation. Copy distinguishes saved encrypted records from unsaved edits.
 */
import { Component, type ReactNode } from "react";
import { Button, Card } from "./ui";

const CRASH_TITLE = "Something went wrong";
const CRASH_BODY =
  "The portal hit an unexpected error. Saved records stay encrypted. Unsaved edits may not have finished saving; retry this view before reloading.";

interface BoundaryState {
  failed: boolean;
}

function CrashPanel({ onRetry, retryLabel }: { onRetry: () => void; retryLabel: string }) {
  return (
    <Card title={CRASH_TITLE} tone="danger">
      <p className="card__note" role="alert">
        {CRASH_BODY}
      </p>
      <div className="row row--wrap">
        <Button label={retryLabel} onPress={onRetry} />
      </div>
    </Card>
  );
}

export class ErrorBoundary extends Component<{ children: ReactNode }, BoundaryState> {
  state: BoundaryState = { failed: false };

  static getDerivedStateFromError(): BoundaryState {
    return { failed: true };
  }

  render(): ReactNode {
    if (this.state.failed) {
      return (
        <main style={{ maxWidth: 560, margin: "10vh auto", padding: "0 24px" }}>
          <CrashPanel onRetry={() => window.location.reload()} retryLabel="Reload the page" />
        </main>
      );
    }
    return this.props.children;
  }
}

/** Per-view boundary: keyed by `resetKey` (the active view), so leaving a
 *  crashed view recovers without a reload. */
export class ViewBoundary extends Component<
  { children: ReactNode; resetKey: string },
  BoundaryState
> {
  state: BoundaryState = { failed: false };

  static getDerivedStateFromError(): BoundaryState {
    return { failed: true };
  }

  componentDidUpdate(prev: { resetKey: string }): void {
    if (prev.resetKey !== this.props.resetKey && this.state.failed) {
      this.setState({ failed: false });
    }
  }

  render(): ReactNode {
    if (this.state.failed) {
      return <CrashPanel onRetry={() => this.setState({ failed: false })} retryLabel="Try again" />;
    }
    return this.props.children;
  }
}
