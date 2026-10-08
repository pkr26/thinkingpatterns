#!/usr/bin/env python3
"""Generate frontend consumer cases using the independent Python brain.

The expected results are outputs of the backend tokenizer, morphology,
sentiment scorer and language gate, never copies of frontend lookup tables.
Regenerate with `.venv/bin/python tools/generate-frontend-brain-behavior.py`.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services import brain
from app.services.patterns import WORD_RE

OUTPUT = ROOT / "shared" / "frontend_brain_behavior.json.gz"


def tokenize(text: str) -> list[str]:
    tokens = WORD_RE.findall(brain._fold_sentiment_text(text.lower()))
    return tokens + brain._emoji_tokens(text)


def language(text: str) -> str:
    folded = brain._fold_sentiment_text(text.lower())
    return brain._analysis_language(
        tokenize(text),
        sum("a" <= char <= "z" for char in folded),
        sum(char.isalpha() for char in folded),
        bool(text),
    )


def build_payload() -> dict:
    scored: dict[tuple[str, str | None], None] = {}

    def add(text: str, languages: tuple[str | None, ...] = (None, "en", "es")) -> None:
        for locale in languages:
            scored[text, locale] = None

    # Both merges are consumed through the real scoring API. The same
    # spelling can have different sentiment under explicit EN and ES.
    vocabulary = sorted(set(brain.SENTIMENT_LEXICON) | set(brain.SENTIMENT_LEXICON_ES))
    for word in vocabulary:
        add(word, ("en", "es"))
    for emoji in brain.EMOJI_VALENCES:
        add(emoji)
        add(emoji.removesuffix("\ufe0f"))
        add(f"{emoji} calm {emoji.removesuffix(chr(0xfe0f))} sad")
    # A partial supplementary-character match must not turn an unrelated
    # pictograph into a known sentiment emoji. Check both presentation forms.
    unknown_emoji_texts = []
    known_emoji_bases = {emoji.removesuffix("\ufe0f") for emoji in brain.EMOJI_VALENCES}
    for codepoint in range(0x1F000, 0x1FB00):
        char = chr(codepoint)
        if char not in known_emoji_bases:
            for form in (char, char + "\ufe0f"):
                unknown_emoji_texts.append(form)
                add(form)
                add(f"happy {form} sad")
    for word in sorted(brain.INTENSIFIERS):
        for context in ("happy", "sad", "not good", "not suicidal", "calm sad"):
            add(f"{word} {context}")
        add(f"{word} {word} good")
        add(f"{word} qzxv qzxv qzxv good")
        # Negators can carry their own valence when no successor is scored;
        # boosters and contrast still apply to that stranded sentiment.
        for negator in sorted(brain.NEGATORS):
            add(f"{word} {negator}")
            add(f"but {word} {negator}")
    for word in sorted(brain.NEGATORS):
        for context in ("happy", "sad", "suicidal", "good bad", "not good"):
            add(f"{word} {context}")
        add(word)
        add(f"{word} {word}")
        add(f"{word} qzxv qzxv qzxv happy")
    for word in sorted(brain.BUT_WORDS):
        add(f"good {word} bad")
        add(f"bad {word} good {word} sad")
    for word in sorted(brain.PERSEVERATIVE_FRAMES):
        for negator in ("not", "can't", "no", "nunca"):
            add(f"{negator} {word} happy")
            add(f"{negator} {word} suicidal")
    # The frontend port does not consume sense_words yet. These text cases
    # still exercise the words through its shipped sentiment consumer;
    # unused sense metadata gets no artifact-equality kill credit.
    for word in sorted(brain.SENSE_WORDS):
        add(f"{word} good")
    for word in ("", "constructor", "__proto__", "quiet day", "don't feel good", "don’t feel good", "depresio\u0301n"):
        add(word)

    sentiment = []
    for text, locale in scored:
        tokens = tokenize(text)
        positive, negative = brain.sentiment_components(tokens, locale)
        sentiment.append([text, locale, brain.sentiment_score(tokens, locale), positive, negative])
    walks: dict[tuple[tuple[str, ...], str | None], None] = {}
    for word in vocabulary:
        for locale in (None, "en", "es"):
            walks[(word,), locale] = None
    for word in sorted(set(brain.NEGATORS) | set(brain.INTENSIFIERS)):
        for context in ("happy", "sad", "feliz", "triste"):
            for tokens in ((word, context), (word, word, context), ("but", word, context)):
                for locale in (None, "en", "es"):
                    walks[tokens, locale] = None
    # Raw callers can strand zero-valence negators without a scored successor.
    # Empty contributions must agree with the backend's token walk as well.
    for word in sorted(brain.NEGATORS):
        for tokens in ((word,), (word, "qzxv"), (word, word)):
            for locale in (None, "en", "es"):
                walks[tokens, locale] = None

    # Single words expose membership changes; balanced bilingual contexts
    # also expose removal from a table when that word exists in both sets.
    language_texts: dict[str, None] = {}
    for word in sorted(brain._KNOWN_TOKENS | brain._KNOWN_TOKENS_ES):
        for text in (word, f"{word} happy", f"{word} feliz"):
            language_texts[text] = None
    for word in ("happy", "feliz"):
        for unknowns in (8, 9, 10, 49, 50):
            language_texts[" ".join([word, *(["qzxv"] * unknowns)])] = None
    for text in ("", " ", "123", "😀", "a an", "qzxv", "北京非常难过 happy", "очень грустно happy", "العربية happy", "happy" + " " * 20, "happy北京你好啊"):
        language_texts[text] = None

    token_texts = [*brain.EMOJI_VALENCES, " ".join(brain.EMOJI_VALENCES), "❤ ☀ ☹", "don’t feel good", "DEPRE SIÓN", "depresio\u0301n", "constructor", "北京 happy"]
    token_texts.extend(unknown_emoji_texts)
    # Public morphology candidates affect the first available scored form.
    # Include every length boundary and both doubled consonants and vowels.
    morphology = set(brain.IRREGULAR_FORMS) | set(vocabulary)
    for suffix in ("ies", "es", "s", "ss", "ing", "ed"):
        for stem in ("", "a", "ab", "abc", "abcd", "abcde", "abcdef"):
            morphology.update((stem + suffix, stem + suffix + "x", suffix + stem))
    for letter in "abcdefghijklmnopqrstuvwxyz":
        for prefix in ("", "a", "ab", "abc"):
            for suffix in ("ing", "ed"):
                morphology.add(prefix + letter * 2 + suffix)
    morphology.update(("studies", "stories", "running", "stopped", "hoped", "hopping", "hoping", "press", "stress", "", "constructor", "__proto__"))
    fold_texts = {"", "ordinary ascii", "don’t feel good", "depresión", "depresio\u0301n", "किरण", "عَرَبِيّ", "😀 café", "𝓐𝓫𝓬", "ﬃ", "①", "ꜱuicide", "cafe\u0301\u0334"}
    for codepoint in range(0x80, 0x250):
        char = chr(codepoint)
        if unicodedata.category(char).startswith("L"):
            fold_texts.add(char)
            fold_texts.add(unicodedata.normalize("NFD", char))
    # Exercise the Latin-mark boundary over the complete Unicode scalar
    # range, including compatibility decompositions and multi-letter bases.
    # Expected results still come only from the backend's component API.
    for codepoint in range(0x110000):
        if 0xD800 <= codepoint <= 0xDFFF:
            continue
        char = chr(codepoint)
        composed = unicodedata.normalize("NFKC", char)
        decomposed = unicodedata.normalize("NFKD", char)
        if (composed != char or decomposed != char) and any(
            "\u0300" <= part <= "\u036f" for part in decomposed
        ):
            for variant in (char, composed, decomposed):
                fold_texts.update((variant, f"ab{variant}", f"happy {variant} sad"))
    token_texts.extend(sorted(fold_texts))
    references = [
        "backend/app/services/brain.py",
        "backend/app/services/patterns.py",
        "backend/app/services/sentiment_lexicon.py",
        "backend/app/services/sentiment_lexicon_es.py",
    ]
    return {
        "version": 1,
        "unicode_version": unicodedata.unidata_version,
        "generator": "tools/generate-frontend-brain-behavior.py",
        "contract": "Frontend sentiment, tokenization, morphology and supported-language eligibility agree with the Python brain component APIs.",
        "reference_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in references},
        "sentiment_columns": ["text", "language_or_null", "score", "positive", "negative"],
        "sentiment": sentiment,
        # The exported TS walk also accepts already-tokenized caller input.
        # Preserve raw accented keys here, independently of text folding.
        "valence_walk": [[list(tokens), locale, brain._valence_walk(list(tokens), locale)] for tokens, locale in walks],
        "tokenize": [[text, tokenize(text)] for text in token_texts],
        "word_forms": [[word, brain.word_forms(word)] for word in sorted(morphology)],
        "fold": [[text, brain._fold_sentiment_text(text)] for text in sorted(fold_texts)],
        "language": [[text, language(text)] for text in language_texts],
    }


def main() -> None:
    payload = build_payload()
    encoded = (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    OUTPUT.write_bytes(gzip.compress(encoded, mtime=0))
    print(f"Wrote {OUTPUT.relative_to(ROOT)}: {len(payload['sentiment'])} scoring cases, {len(payload['language'])} language cases, {len(payload['tokenize'])} tokenizer cases, {len(payload['word_forms'])} morphology cases, {len(payload['fold'])} Unicode folding cases")


if __name__ == "__main__":
    main()
