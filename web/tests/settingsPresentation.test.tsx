import { SettingsView } from "../src/views/Settings";
import { viewPresentation } from "./helpers/viewPresentation";
viewPresentation("Account settings", () => <SettingsView onLockdown={() => {}} onOpenSafetyPlan={() => {}} />);
