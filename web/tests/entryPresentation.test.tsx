import { EntryView } from "../src/views/Entry";
import { viewPresentation } from "./helpers/viewPresentation";
viewPresentation("Journal entry", () => <EntryView onSaved={() => {}} onCrisis={() => {}} />);
