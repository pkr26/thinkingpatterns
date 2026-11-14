"""The documented language-asset CLI preserves the released TS-port reference."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from app.services import brain


def test_actual_language_export_cli_preserves_the_released_crossplatform_reference(tmp_path):
    backend = Path(brain.__file__).resolve().parents[2]
    script = backend / "scripts/dump_brain_lexicon.py"
    isolated = tmp_path / "native-export"
    copied_script = isolated / "backend/scripts/dump_brain_lexicon.py"
    copied_script.parent.mkdir(parents=True)
    shutil.copyfile(script, copied_script)
    targets = [
        "shared/brain_lexicon.json",
        "mobile/src/brain/lexicon.ts",
        "web/src/brain/lexicon.ts",
    ]
    for target in targets:
        (isolated / target).parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "PYTHONPATH": str(backend), "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run(
        [sys.executable, "-B", str(copied_script)],
        cwd=backend,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    reference = json.loads((backend.parent / targets[0]).read_text())
    assert json.loads((isolated / targets[0]).read_text()) == reference
    for target in targets[1:]:
        generated = (isolated / target).read_text().split("export const LEXICON = ", 1)[1]
        assert json.loads(generated.removesuffix(";\n")) == reference
