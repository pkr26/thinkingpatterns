#!/usr/bin/env python3
"""Derive text-level frontend crisis cases from the independent Python engine.

Pattern syntax generates inputs, never expected regex/array values. Every
branch and optional term gets a real text witness; expectations come from the
backend's public dialog and suppression consumers. Regenerate with the venv.
"""
from __future__ import annotations

import gzip
import hashlib
import itertools
import json
import sys
import unicodedata
from pathlib import Path
from re import _constants as constants
from re import _parser as parser

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.services import crisis

OUTPUT = ROOT / "shared" / "frontend_crisis_behavior.json.gz"


def texts(sequence) -> list[str]:
    result = [""]
    for operation, value in sequence:
        if operation is constants.LITERAL:
            choices = [chr(value)]
        elif operation is constants.AT:
            choices = [""]
        elif operation is constants.SUBPATTERN:
            choices = texts(value[-1])
        elif operation is constants.BRANCH:
            choices = [text for branch in value[1] for text in texts(branch)]
        elif operation in (constants.MAX_REPEAT, constants.MIN_REPEAT):
            minimum, _maximum, child = value
            # All optional choices, one minimum-length representative of
            # unbounded runs. Whitespace variations are added separately.
            counts = [0, 1] if minimum == 0 else [minimum]
            choices = ["".join(parts) for count in counts for parts in itertools.product(texts(child), repeat=count)]
        elif operation is constants.IN:
            choices = []
            for kind, item in value:
                if kind is constants.LITERAL:
                    choices.append(chr(item))
                elif kind is constants.CATEGORY and item is constants.CATEGORY_SPACE:
                    choices.append(" ")
                elif kind is constants.CATEGORY and item is constants.CATEGORY_WORD:
                    choices.append("a")
                else:
                    raise ValueError(f"Unsupported character class: {(kind, item)}")
        else:
            raise ValueError(f"Unsupported regex operation: {operation}")
        result = list(dict.fromkeys(prefix + choice for prefix in result for choice in choices))
    return result


def build_payload() -> dict:
    contract = json.loads((ROOT / "shared/crisis_phrases.json").read_text())
    cases: dict[str, None] = {}
    witnesses = []

    def add(text: str) -> None:
        cases[text] = None

    for tier in ("dialog", "suppress_extra"):
        for index, pattern in enumerate(contract[tier]):
            samples = texts(parser.parse(pattern, 0))
            witnesses.append({"tier": tier, "index": index, "alternatives": len(samples), "texts": samples})
            for sample in samples:
                add(sample)
                # Branch-specific group seams must have independent
                # witnesses too; the first branch cannot stand in for
                # every optional suffix or nested alternative.
                for position in range(1, len(sample)):
                    if sample[position - 1].isalpha() and sample[position].isalpha():
                        add(sample[:position] + " " + sample[position:])
            # Exercise normalization and the word-boundary contract using
            # a representative for each independent pattern family.
            sample = samples[0]
            for transformed in (sample.upper(), f"today {sample} tonight", sample.replace(" ", "\t"), sample.replace(" ", "  "), sample.replace(" ", "-")):
                add(transformed)
            # Mathematical capitals are unchanged by lowercase but turn
            # into ASCII capitals during compatibility normalization.
            # This exercises case-insensitive matching after NFKC.
            add("".join(chr(0x1D400 + ord(char) - ord("a")) if "a" <= char <= "z" else char for char in sample))
            # Exercise real evasion seams and the folded matcher separately:
            # missing spaces, a split inside each word, and a doubled letter
            # must agree with the independent engine's public decision.
            add(sample.replace(" ", ""))
            add(" ".join(sample))
            for position, char in enumerate(sample):
                if char.isalpha():
                    add(sample[:position] + "😊" + sample[position + 1:])
            words = sample.split(" ")
            for word_index, word in enumerate(words):
                for seam in range(1, len(word)):
                    if word[seam - 1].isalpha() and word[seam].isalpha():
                        changed = words.copy()
                        changed[word_index] = word[:seam] + " " + word[seam:]
                        add(" ".join(changed))
                for position, char in enumerate(word):
                    if "a" <= char <= "z":
                        changed = words.copy()
                        changed[word_index] = word[:position] + char + word[position:]
                        add(" ".join(changed))
                        # Apostrophes retain a real word boundary in the
                        # primary matcher while preventing token-concat
                        # fallback from starting at the embedded phrase.
                        add("x'" + " ".join(changed))
            for extension in ("x", "s", "line", "board", "field", "on"):
                add(sample + extension)
            add("week" + sample)
    for compound in contract["benign_compounds"]:
        for transformed in (compound, compound.upper(), f"we discussed {compound} today", compound.replace(" ", "-"), compound.replace(" ", "\t"), compound.replace(" ", ", "), f"{compound} but I want to die"):
            add(transformed)
        for position, char in enumerate(compound):
            if "a" <= char <= "z":
                add(compound[:position] + char + compound[position:])
        add("".join(char * 2 if "a" <= char <= "z" else char for char in compound))
        add("x" + compound)
        add(compound + "x")
        add(compound + " and " + compound)
        add("x'" + compound + "'y")
        add("x'" + "".join(char * 2 if "a" <= char <= "z" else char for char in compound) + "'y")
        add("".join(chr(0x1D400 + ord(char) - ord("a")) if "a" <= char <= "z" else char for char in compound))
    for values in contract["fixtures"].values():
        for sample in values:
            add(sample)
    for row in contract["redteam_corpus"]:
        add(row["sample"])
    # Text-level normalization is a public cross-engine contract too. Feed
    # each confusable/invisible/leet input through it, with boundary contexts,
    # rather than pinning either frontend's private normalization maps.
    for codepoint in crisis._HOMOGLYPHS:
        char = chr(codepoint)
        for sample in (char, f"a{char}b", f"{char}uicide", f"kill my{char}elf"):
            add(sample)
    for codepoint in crisis._INVISIBLE:
        char = chr(codepoint)
        add(f"sui{char}cide")
        add(f"calm{char}day")
    for char in crisis._LEET:
        for sample in (f"a{char}b", f"a{char}f", f"{char}abc", f"abc{char}", f"abc{char}!", f"word {char}abc", f"abc{char}{char}"):
            add(sample)
    for sample in ("a b c", "a b c d", "a b c d e", "i a b word", "k ill myself", "a i word", "end it all", "a漢b", "漢a", "a漢", "a😊b", "😀abc", "abc😀", "a😊b😊c😊d", "sui\nci\tde", "sin hacer daño", "किरण", "عَرَبِيّ", "가나다", "𐐀abc"):
        add(sample)
    for letter in ("a", "z", "0", "9", "1", "8", "A", "Z", "'", "-", ":", "`", "@"):
        for script in ("漢", "क", "ع", "𐐀", "😊", "÷", "é", "ǅ"):
            for sample in (letter + script, script + letter, letter + script + letter):
                add(sample)
    for codepoint in range(0x80, 0x3000):
        char = chr(codepoint)
        if char.isalpha() and unicodedata.normalize("NFKD", char) != char:
            add(char)
            add("a" + char + "b")
    for sample in ("i want to s.l.e😊p forever", "k😊i😊ll mys😊lf", "😊nd it all", "k3lf", "k4lf", "k5lf", "k8lf", "abc13!", "abc13😊", "abc13-", "abc13 "):
        add(sample)
    for sample in (" a b c ", " a b c d ", "a--b--c--d", "z z z z", "0 9 a z", "i w a nt to die", "i w an t to die", "i w a n t to die", "i a m suicidal", "k😊ll my😊elf", "s😊ic😊de", "a😊b😊c😊d😊e", "a\u0301\u0308bc", "\u1e69", "\ufb03", "\u3392", "\u337f", "\u1e9b\u0323"):
        add(sample)
    for length in range(7):
        for suffix in ("word", "a", "", "die", "myself"):
            add(" ".join(list("abcdef"[:length]) + [suffix]))
    for sample in ("", "A calm ordinary afternoon", "weekend it all", "rocky sunset", "lucky star", "I wanna diet", "deadline tomorrow", "online today", "I am ashamed of myself"):
        add(sample)
    rows = [[text, crisis.matches_dialog(text), crisis.matches_suppress(text)] for text in cases]
    inputs = ["backend/app/services/crisis.py", "shared/crisis_phrases.json"]
    return {"version": 1, "oracle": "Independent Python crisis decisions, normalization, and documented cross-engine variant output", "sourceHashes": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in inputs}, "witnesses": witnesses, "rows": rows, "normalize": [[text, crisis.normalize_crisis_text(text)] for text in cases], "variants": [[text, list(crisis._match_variants(text)), list(crisis._folded_variants(text))] for text in cases]}


def main() -> None:
    payload = build_payload()
    serialized = (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    OUTPUT.write_bytes(gzip.compress(serialized, mtime=0))
    print(f"{OUTPUT.relative_to(ROOT)}: {len(payload['rows'])} text cases, {len(payload['witnesses'])} pattern families")


if __name__ == "__main__":
    main()
