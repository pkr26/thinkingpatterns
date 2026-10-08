import { expect, it, vi } from "vitest";
import { Privacy } from "../src/views/Privacy";
import { viewPresentation } from "./helpers/viewPresentation";
import { press, render } from "./helpers/rtr";
viewPresentation("Privacy disclosures", () => <Privacy onBack={() => {}} />);
it("returns from the privacy disclosure using its visible back control", async () => {
  const back = vi.fn(); const root = await render(<Privacy onBack={back} />); await press(root, "Back"); expect(back).toHaveBeenCalledOnce();
});
