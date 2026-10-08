import { SafetyPlanView } from "../src/views/SafetyPlan";
import { viewPresentation } from "./helpers/viewPresentation";
viewPresentation("Local safety plan", () => <SafetyPlanView onCrisis={() => {}} />);
