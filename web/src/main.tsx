import { createRoot } from "react-dom/client";
import { App } from "./App";
import { initTheme } from "./theme";

// Apply the saved/system theme BEFORE first paint so the boot beat never
// flashes the wrong color scheme (no-op outside the DOM).
initTheme();

const container = document.getElementById("root");
if (!container) throw new Error("#root missing in index.html");
createRoot(container).render(<App />);
