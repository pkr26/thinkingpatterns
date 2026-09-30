"""2026-09-29 deep-audit CRITICAL remediation: method-specific ideation.

The audit executed the live matcher and found that method-specific
first-person ideation fired NEITHER crisis tier — the client support
dialog never appeared AND the phrase miner could quote the sentence
verbatim on a rumination card ("the thought 'i want to hang myself'
keeps returning"), the exact harm the crisis interlock exists to
prevent. These tests pin the closed gap and the deliberate benign
boundaries (medication adherence must not fire).
"""

from __future__ import annotations

from app.services.crisis import matches_dialog, matches_suppress


METHOD_PHRASES = (
    # The exact audit corpus: every row fired neither tier before.
    "i want to hang myself",
    "i am going to hang myself tonight",
    "i will shoot myself",
    "thinking about drowning myself",
    "i want to cut my wrists",
    "going to swallow all my pills",
    "i am going to jump off the bridge tomorrow",
    "i deserve to die",
    "i should be dead already",
    # Adjacent forms of the same families.
    "hung myself once before",
    "planning to jump off the roof",
    "swallowed the whole bottle last night",
    "sometimes i slit my wrists",
    "i want to be dead",  # was suppress-only before the promotion
)


class TestMethodSpecificIdeationFiresBothTiers:
    def test_dialog_tier_fires(self) -> None:
        for phrase in METHOD_PHRASES:
            assert matches_dialog(phrase), f"dialog tier missed: {phrase!r}"

    def test_suppress_tier_fires(self) -> None:
        # Suppression is what keeps the phrase miner from quoting these
        # sentences back on rumination cards — the second half of the harm.
        for phrase in METHOD_PHRASES:
            assert matches_suppress(phrase), f"suppress tier missed: {phrase!r}"


class TestMedicationAdherenceStaysBenign:
    """The pill patterns deliberately require "all (of) my pills" / "the
    whole bottle" — ordinary adherence phrasing must not trigger the
    support dialog (a daily false positive trains dismissal)."""

    DIALOG_SILENT = (
        "i take my pills every morning with breakfast",
        "taking my pills with food like the doctor said",
        "i swallow my pills with a big glass of water",
        "don't forget to take my pills tonight",
    )

    def test_adherence_never_fires_dialog(self) -> None:
        for phrase in self.DIALOG_SILENT:
            assert not matches_dialog(phrase), f"dialog false positive: {phrase!r}"

    def test_hung_picture_is_not_hanging(self) -> None:
        assert not matches_dialog("i hung the picture myself")
        assert not matches_suppress("i hung the picture myself")


class TestSpanishHangingParity:
    """The ES self-harm families gained ahorcar (to hang) — parity with
    the investment the repo already made in Spanish coverage."""

    def test_ahorcar_forms_fire_dialog(self) -> None:
        for phrase in ("me quiero ahorcar", "quiero ahorcarme", "me voy a ahorcar"):
            assert matches_dialog(phrase), f"dialog tier missed: {phrase!r}"
            assert matches_suppress(phrase), f"suppress tier missed: {phrase!r}"


class TestNonFirstPersonJumpIsSuppressOnly:
    """News-style third-person mentions are never a dialog trigger, but
    must still be suppressed so they are not quoted back as patterns."""

    def test_news_jump_suppress_only(self) -> None:
        phrase = "someone jumped off a bridge in the news"
        assert not matches_dialog(phrase)
        assert matches_suppress(phrase)
