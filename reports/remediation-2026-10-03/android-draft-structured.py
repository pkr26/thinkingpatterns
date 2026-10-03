"""Owned emulator/synthetic audit-eve fixture only; creates one journal entry.

Requires the debug build, Metro on 8081, API on localhost:8918 and ADB reverse.
This is emulator restart evidence, not a release or physical-device test.
"""

from pathlib import Path
import re
import subprocess
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
ADB = Path.home() / "Library/Android/sdk/platform-tools/adb"
DEVICE = "emulator-5562"
REPORT = Path(__file__).resolve().parent
DRAFT = "Synthetic final native structured draft restart retention."


def adb(*args):
    return subprocess.check_output([str(ADB), "-s", DEVICE, *args], text=True, timeout=30)


def nodes():
    adb("shell", "uiautomator", "dump", "/sdcard/remediation-ui.xml")
    raw = adb("exec-out", "cat", "/sdcard/remediation-ui.xml")
    (ROOT / ".tools/android-current-ui.xml").write_text(raw)
    return list(ET.fromstring(raw).iter("node"))


def matching(label, current):
    return [n for n in current if n.get("content-desc") == label or n.get("text") == label]


def scroll(direction):
    start, end = (1840, 580) if direction == "down" else (580, 1840)
    adb("shell", "input", "swipe", "540", str(start), "540", str(end), "350")


def find(label):
    for direction in ("down", "up"):
        for _ in range(6):
            found = matching(label, nodes())
            if found:
                return found[0]
            scroll(direction)
    raise AssertionError(f"Missing accessible control: {label}")


def tap(label):
    control = find(label)
    # The debug build's upstream warning banner can cover navigation. Close
    # only its observed close control; secure-screen protection stays enabled.
    observed = ET.fromstring((ROOT / ".tools/android-current-ui.xml").read_text())
    for warning in observed.iter("node"):
        if "Open debugger to view warnings" not in warning.get("content-desc", ""):
            continue
        for close in warning.iter("node"):
            if close.get("NAF") == "true" and close.get("clickable") == "true":
                left, top, right, bottom = map(int, re.findall(r"\d+", close.get("bounds")))
                adb("shell", "input", "tap", str((left + right) // 2), str((top + bottom) // 2))
                control = find(label)
    left, top, right, bottom = map(int, re.findall(r"\d+", control.get("bounds")))
    assert right > left and bottom > top
    adb("shell", "input", "tap", str((left + right) // 2), str((top + bottom) // 2))


def fill(label, value):
    tap(label)
    adb("shell", "input", "keyevent", "123")
    adb("shell", "input", "keyevent", *(["67"] * 100))
    adb("shell", "input", "text", value.replace(" ", "%s"))
    adb("shell", "input", "keyevent", "4")


def wait_for(predicate, timeout=35):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        current = nodes()
        if predicate(current):
            return current
        time.sleep(1)
    raise AssertionError("Expected state did not arrive before timeout")


def snapshot(name):
    (REPORT / name).write_text((ROOT / ".tools/android-current-ui.xml").read_text())


def restart_unlock():
    adb("shell", "am", "force-stop", "com.mindpattern")
    adb("shell", "am", "start", "-n", "com.mindpattern/.MainActivity")
    wait_for(lambda ns: matching("Password", ns))
    fill("Password", "audit-eve-2026")
    tap("Unlock")
    wait_for(lambda ns: matching("Journal entry", ns))
    find("11/30 days to your patterns")


def selected(label, attribute):
    control = find(label)
    assert control.get(attribute) == "true", (label, control.attrib)


if __name__ == "__main__":
    restart_unlock()
    editor = find("Journal entry")
    assert editor.get("text") in ("", "What's going on today?", DRAFT), "Use a blank synthetic fixture or this probe's own draft"
    fill("Journal entry", DRAFT)
    tap("Add details (optional)")
    for label in ("Mood: Good", "Energy: Steady", "Sleep: Good", "Tag: rest"):
        attribute = "checked" if label.startswith("Tag:") else "selected"
        if find(label).get(attribute) != "true":
            tap(label)
    tap("Hide details")
    find("Encrypted draft saved on this device")
    snapshot("android-structured-draft-saved-ui.xml")
    print("PASS native typed text and four optional details reach encrypted persistence", flush=True)

    restart_unlock()
    assert find("Journal entry").get("text") == DRAFT
    tap("Add details (optional)")
    for label in ("Mood: Good", "Energy: Steady", "Sleep: Good"):
        selected(label, "selected")
    selected("Tag: rest", "checked")
    snapshot("android-structured-draft-restored-ui.xml")
    tap("Hide details")
    print("PASS real process restart/unlock restores text, mood, energy, sleep, tag and 11/30 progress", flush=True)

    tap("Save entry")
    wait_for(lambda ns: any(n.get("content-desc") == "Journal entry" and n.get("text") != DRAFT for n in ns))
    snapshot("android-structured-draft-ack-ui.xml")
    tap("History")
    wait_for(lambda ns: not matching("Journal entry", ns))
    find(DRAFT)
    snapshot("android-structured-draft-history-ui.xml")
    print("PASS native acknowledged save decrypts in History", flush=True)
    tap("Today")
    restart_unlock()
    assert find("Journal entry").get("text") != DRAFT
    current = nodes()
    assert not matching("Draft restored", current)
    snapshot("android-structured-draft-after-ack-ui.xml")
    print("PASS second restart has no acknowledged draft resurrection and authoritative 11/30 progress", flush=True)
