import { afterEach, describe, expect, it, vi } from "vitest";
import { act } from "react";
import { activityTagLabel, ENERGY_OPTIONS, moodLabel, MOOD_OPTIONS, optionLabel, SLEEP_OPTIONS } from "../src/mood";
import { __setLocaleForTests } from "../src/strings";
import { BarScale, DotScale, MoodScale } from "../src/ui";
import { render } from "./helpers/rtr";

afterEach(() => __setLocaleForTests("en"));

describe("check-in vocabulary through the visible controls", () => {
  it.each([
    ["mood", MOOD_OPTIONS, MoodScale, ["Heavy", "Low", "Okay", "Good", "Light"], [-1, -0.5, 0, 0.5, 1]],
    ["energy", ENERGY_OPTIONS, BarScale, ["Drained", "Steady", "Energized"], [-1, 0, 1]],
    ["sleep", SLEEP_OPTIONS, DotScale, ["1 — Rough", "2 — Poor", "3 — Okay", "4 — Good", "5 — Rested"], [1, 2, 3, 4, 5]],
  ] as const)("%s controls expose every expected label and submit its stable numeric value", async (_kind, options, Control, labels, values) => {
    __setLocaleForTests("en");
    const onChange = vi.fn();
    const root = await render(<Control options={options} value={null} onChange={onChange} groupLabel="Check-in" />);
    const buttons = root.root.findAllByType("button");
    expect(buttons.map((button) => button.props["aria-label"])).toEqual(labels);
    for (let index = 0; index < buttons.length; index++) {
      await act(async () => { buttons[index]!.props.onClick(); });
      expect(onChange).toHaveBeenLastCalledWith(values[index]);
    }
  });

  it("renders the option catalog key through the public label helper", () => {
    __setLocaleForTests("en");
    expect(optionLabel({ labelKey: "energy.option.drained" })).toBe("Drained");
    __setLocaleForTests("es");
    expect(optionLabel({ labelKey: "energy.option.drained" })).toBe("Baja");
  });

  it("chooses the nearest mood label and the lower pick at an exact midpoint", () => {
    __setLocaleForTests("en");
    for (const [value, expected] of [[-1, "Heavy"], [-0.75, "Heavy"], [-0.749, "Low"], [-0.5, "Low"], [-0.25, "Low"], [-0.249, "Okay"], [0, "Okay"], [0.25, "Okay"], [0.251, "Good"], [0.5, "Good"], [0.75, "Good"], [0.751, "Light"], [1, "Light"]] as const) {
      expect(moodLabel(value)).toBe(expected);
    }
  });

  it("localizes each supported activity token and preserves an unknown token", () => {
    const expected = [
      ["work", "work", "Trabajo"], ["family", "family", "Familia"], ["friends", "friends", "Amistades"],
      ["exercise", "exercise", "Ejercicio"], ["outdoors", "outdoors", "Aire libre"], ["rest", "rest", "Descanso"],
      ["creative", "creative", "Creatividad"], ["health", "health", "Salud"], ["money", "money", "Dinero"], ["travel", "travel", "Viaje"],
    ];
    for (const [tag, english, spanish] of expected) {
      __setLocaleForTests("en");
      expect(activityTagLabel(tag!)).toBe(english);
      __setLocaleForTests("es");
      expect(activityTagLabel(tag!)).toBe(spanish);
    }
    expect(activityTagLabel("another-client-tag")).toBe("another-client-tag");
  });
});
