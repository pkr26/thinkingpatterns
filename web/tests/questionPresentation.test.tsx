import { QuestionView } from "../src/views/Question";
import { viewPresentation } from "./helpers/viewPresentation";
viewPresentation("Writing question", () => <QuestionView onRefreshed={() => {}} />);
