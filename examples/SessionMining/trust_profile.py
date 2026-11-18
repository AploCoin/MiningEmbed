"""Reuse the AploEmbed checkout's offline trust profile generator."""

import os
from pathlib import Path

Import("env")
script = Path(os.environ["APLOEMBED_PATH"]) / "tools/trust/platformio.py"
env.SConscript(str(script), exports="env")
