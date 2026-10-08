import { LoginView } from "../src/views/LoginView";
import { viewPresentation } from "./helpers/viewPresentation";
viewPresentation("Sign in", () => <LoginView onSuccess={() => {}} />);
