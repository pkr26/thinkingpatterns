/**
 * crisisDetect: the on-device, pre-encryption crisis-language matcher.
 * Pins every phrase family (a silent regression here means a missed
 * crisis), the case/whitespace tolerance of quick typing, and — just as
 * important — that everyday journal text does NOT trip it.
 */
import { describe, expect, it } from "vitest";
import { detectCrisisLanguage } from "../src/crisisDetect";

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
  ])("fires on %j", (text) => {
    expect(detectCrisisLanguage(text)).toBe(true);
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
  ])("does NOT fire on %j", (text) => {
    expect(detectCrisisLanguage(text)).toBe(false);
  });

  it("accepts the deliberate false positive: even 'suicide prevention' context", () => {
    // "suicide" is high-signal enough that the matcher fires on any use of
    // the word — the cost is one gentle dialog, the benefit is no misses.
    expect(detectCrisisLanguage("We discussed suicide prevention policy in class today.")).toBe(true);
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
