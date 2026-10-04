import { createRoot } from "react-dom/client";
import { App } from "./App";
import { ErrorBoundary } from "./ErrorBoundary";
import { initTheme } from "./theme";

// The reactive theme half: public/theme-init.js already resolved
// <html data-theme> synchronously in <head> (pre-paint); this installs
// live OS tracking for "auto" and stays idempotent with that script
// (no-op outside the DOM).
initTheme();

const container = document.getElementById("root");
if (!container) throw new Error("#root missing in index.html");
createRoot(container).render(
  <ErrorBoundary>
    <App />
  </ErrorBoundary>,
);
