/**
 * crisisDetect: the on-device, pre-encryption crisis-language matcher.
 * Pins every phrase family (a silent regression here means a missed
 * crisis), the case/whitespace tolerance of quick typing, and — just as
 * important — that everyday journal text does NOT trip it.
 */
import { describe, expect, it } from "vitest";
import { detectCrisisLanguage, matchVariants, normalizeCrisisText } from "../src/crisisDetect";

describe("detectCrisisLanguage — true positives", () => {
  it.each([
    // Direct suicidal statements (each phrase family).
    "I keep thinking about how to kill myself",
    "i have been thinking about killing myself",
    "the note mentioned suicide twice",
    "I feel suicidal tonight",
    "I want to die",
    "i wanted to die back then",
    "I just wanna die sometimes",
    "I wish I was dead",
    "I wish i were dead",
    // Ending it.
    "I just want to end it all",
    "thinking about ending it all",
    "I want to end my life",
    "plans for ending my life",
    "thinking about how to take my own life",
    "afraid I will take my life",
    // Self-harm.
    "I keep slipping back into self harm",
    "the self-harm started again",
    "i am self harming again",
    "I want to hurt myself",
    "I keep hurting myself",
    // Hopelessness phrases.
    "there is no reason to live anymore",
    "no reason to go on",
    "I can't go on like this",
    "i cant go on",
    "I cannot go on anymore",
    "everyone would be better off without me",
    "I don't want to be here",
    "i dont want to live",
    "I do not want to exist",
    // M2 additions: purpose-in-life, be-alive, death-wish gerunds/infinitives,
    // and the cut-myself self-harm family.
    "there is nothing to live for",
    "i have nothing to live for anymore",
    "I don't want to be alive",
    "i do not want to be alive",
    "wanting to die more days than not",
    "i keep wanting to die",
    "i feel like dying",
    "lately everything feels like dying inside",
    "wish i could die",
    "I wish I could die in my sleep",
    "i cut myself again",
    "i have been cutting myself",
  ])("fires on %j", (text) => {
    expect(detectCrisisLanguage(text)).toBe(true);
  });

  // iOS Smart Punctuation substitutes U+2019 for ASCII ' by default — every
  // apostrophe-tolerant family must fire on BOTH spellings or iPhone typing
  // silently misses detection.
  const CURLY = "\u2019";
  it.each([
    `I can${CURLY}t go on`,
    `i don${CURLY}t want to live`,
    `I don${CURLY}t want to be here`,
    `don${CURLY}t want to be alive`,
    `i don${CURLY}t want to exist`,
  ])("fires on the curly-apostrophe (U+2019) variant %j", (text) => {
    expect(detectCrisisLanguage(text)).toBe(true);
  });

  it("still fires on the ASCII and dropped-apostrophe variants", () => {
    expect(detectCrisisLanguage("I can't go on")).toBe(true);
    expect(detectCrisisLanguage("i cant go on")).toBe(true);
    expect(detectCrisisLanguage("I cannot go on")).toBe(true);
    expect(detectCrisisLanguage("i dont want to live")).toBe(true);
    expect(detectCrisisLanguage("I do not want to live")).toBe(true);
  });

  it("is case-insensitive, including ALL CAPS and mixed case", () => {
    expect(detectCrisisLanguage("I WANT TO DIE")).toBe(true);
    expect(detectCrisisLanguage("I wAnT tO eNd It AlL")).toBe(true);
    expect(detectCrisisLanguage("SUICIDAL")).toBe(true);
  });

  it("fires when the phrase is buried in a longer entry", () => {
    const entry =
      "Work was fine and the kids were sweet at dinner, but if I am honest " +
      "with myself I keep coming back to the thought that they would be " +
      "better off without me. I will try to sleep now.";
    expect(detectCrisisLanguage(entry)).toBe(true);
  });

  it("tolerates extra whitespace and newlines inside phrases", () => {
    expect(detectCrisisLanguage("I want  to\n die")).toBe(true);
    expect(detectCrisisLanguage("no  reason\tto live")).toBe(true);
  });
});

describe("detectCrisisLanguage — true negatives", () => {
  it.each([
    // Ordinary journal text.
    "Had a good day. Walked the dog, finished the report, called mom.",
    "The assessment at work was brutal but I passed it.",
    "That workout killed my legs — I can barely walk.",
    "This traffic is killing me.",
    "My boss would kill me if I missed that deadline.",
    "I was dying of laughter at the show.",
    "I'm dead tired after the red-eye.",
    "I killed it at the presentation today.",
    "Feeling anxious about the move but also excited.",
    "I want to diet again starting Monday.",
    "The exam ends, it all comes down to Friday.",
    // Near-misses for the M2 additions.
    "I have nothing to lose.",
    "the new hire has nothing to live up to",
    "i do want to be alive",
    "i want to be alive for my kids",
    "I wish I could fly",
    "feels like a dying art form",
    "i need to cut my hair this weekend",
    "his cutting remarks stung all day",
  ])("does NOT fire on %j", (text) => {
    expect(detectCrisisLanguage(text)).toBe(false);
  });

  it("stays silent on benign compounds (masked since 2026-09-17): titles and campaigns", () => {
    // "suicide squad"/"suicide prevention"/... are masked from both tiers —
    // the bare topic word inside them is not first-person ideation. Every
    // OTHER use of the word still fires (see the true-positive block).
    expect(detectCrisisLanguage("We discussed suicide prevention policy in class today.")).toBe(false);
    expect(detectCrisisLanguage("that movie was suicide squad and i liked it")).toBe(false);
    expect(detectCrisisLanguage("listening to suicide silence again")).toBe(false);
  });

  it("still fires on the word 'suicide' outside the benign compounds", () => {
    expect(detectCrisisLanguage("thinking about suicide again")).toBe(true);
    expect(detectCrisisLanguage("the suicide prevention lecture left me suicidal")).toBe(true);
  });

  it("accepts the documented false positives: benign 'cut myself' / 'feel like dying' contexts", () => {
    // A clean context distinction ("shaving", "chopping onions", gym
    // hyperbole) would be an incomplete blocklist pretending to be
    // precision — see the crisisDetect header. The conservative contract
    // pays one gentle dialog instead of risking a miss.
    expect(detectCrisisLanguage("I cut myself shaving this morning")).toBe(true);
    expect(detectCrisisLanguage("I feel like dying after that workout")).toBe(true);
  });

  it("does not fire on empty or whitespace-only input", () => {
    expect(detectCrisisLanguage("")).toBe(false);
    expect(detectCrisisLanguage("   \n\t  ")).toBe(false);
  });

  it("does not fire on partial-word lookalikes", () => {
    expect(detectCrisisLanguage("the assessment was nothing relevant")).toBe(false);
    expect(detectCrisisLanguage("a dying breed of craftsman")).toBe(false);
    expect(detectCrisisLanguage("the suicidology textbook")).toBe(false);
  });
});

describe("dual-variant matching + benign masking (2026-09-17)", () => {
  it("fires on partial-split evasion: orphan single letters glue onto the next word", () => {
    // The documented "k ill myself" residual bypass, now closed on both engines.
    expect(detectCrisisLanguage("k ill myself")).toBe(true);
    expect(detectCrisisLanguage("o ff myself tonight")).toBe(true);
    expect(detectCrisisLanguage("k i ll myself")).toBe(true);
    expect(detectCrisisLanguage("s uicide is on my mind")).toBe(true);
  });

  it("the orphan variant never manufactures matches from ordinary prose", () => {
    expect(detectCrisisLanguage("i am so sad today")).toBe(false);
    expect(detectCrisisLanguage("i want to diet")).toBe(false);
    expect(detectCrisisLanguage("u s a won gold")).toBe(false);
    expect(detectCrisisLanguage("a way out of the city")).toBe(false);
  });

  it("matchVariants returns the primary and orphan forms, benign compounds masked in both", () => {
    const [primary, orphan] = matchVariants("k ill myself after that suicide squad movie");
    expect(primary).toBe("k ill myself after that   movie");
    expect(orphan).toBe("kill myself after that   movie"); // glued AND masked
  });

  it("the primary variant equals normalizeCrisisText on compound-free text", () => {
    const text = "s u i c i d e notes everywhere";
    expect(matchVariants(text)[0]).toBe(normalizeCrisisText(text));
  });
});
