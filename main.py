import os
import shutil
import sys

here = os.path.dirname(os.path.abspath(__file__))
binary = os.path.join(here, "forge-linux-amd64")
if os.name == "nt":
    binary = os.environ.get("MAKEFUN_WIN_FORGE_EXE") or os.path.join(
        here, "target", "release", "forge.exe"
    )
    os.execv(binary, [binary])

try:
    os.execv(binary, [binary])
except OSError:
    tmp_bin = "/tmp/forge-linux-amd64"
    try:
        shutil.copyfile(binary, tmp_bin)
        os.chmod(tmp_bin, 0o755)
    except OSError as exc:
        sys.stderr.write(f"Failed to stage forge binary: {exc}\n")
        sys.exit(1)
    os.execv(tmp_bin, [tmp_bin])
