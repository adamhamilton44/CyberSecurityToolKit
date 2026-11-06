#!/usr/bin/env bash
# Rebuild both maintained entry points from an explicit build environment.
set -euo pipefail
build_python=${1:?Usage: build_engagement_reporting.sh /absolute/build-venv/bin/python}
[[ "$build_python" == /* ]] || { echo 'Use an absolute build Python.' >&2; exit 2; }
build_scope=${2:-all}
[[ "$build_scope" == all || "$build_scope" == --engagement-only ]] || { echo 'Second argument must be --engagement-only or all.' >&2; exit 2; }
compressor=$(command -v upx || command -v upx-ucl || true)
[[ -n "$compressor" ]] || { echo 'UPX is required (upx or upx-ucl).' >&2; exit 2; }
root=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
# Concurrent builds must not clean each other's binary cache.
export PYINSTALLER_CONFIG_DIR="$stage/pyinstaller-cache"
: > "$stage/docx-parts-directory.marker"
"$build_python" -m PyInstaller --clean --noconfirm --onefile --strip \
    --name Etc_engagement --paths "$root/scripts/source/cstk_ai" \
    --paths "$root/scripts/source/reporting" --collect-data docx \
    --add-data "$root/scripts/source/cstk_ai/engagement_scoping_cheat_sheet.md:." \
    --add-data "$root/scripts/source/cstk_ai/engagement_form_template.json:." \
    --add-data "$stage/docx-parts-directory.marker:docx/parts" \
    --distpath "$stage/dist" --workpath "$stage/build" --specpath "$stage/spec" \
    "$root/scripts/source/cstk_ai/engagement_runtime.py"
"$compressor" -9 "$stage/dist/Etc_engagement"
install -m 755 "$stage/dist/Etc_engagement" "$root/scripts/bin/Etc_engagement"
"$build_python" - "$root" <<'PYMETA'
import hashlib, json, platform, sys
from pathlib import Path
import PyInstaller
root = Path(sys.argv[1])
files = ['scripts/source/cstk_ai/cstk_engagement.py', 'scripts/source/cstk_ai/engagement_wizard.py',
         'scripts/source/cstk_ai/engagement_runtime.py', 'scripts/source/cstk_ai/engagement_scoping_cheat_sheet.md',
         'scripts/bin/Etc_engagement']
metadata = {'python': platform.python_version(), 'pyinstaller': PyInstaller.__version__,
            'platform': platform.platform(), 'sha256': {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in files}}
(root/'scripts/source/cstk_ai/ENGAGEMENT_BUILD.json').write_text(json.dumps(metadata,indent=2)+'\n')
PYMETA
if [[ "$build_scope" == all ]]; then
    bash "$root/scripts/source/reporting/build_binary.sh" "$build_python" "$root/scripts/bin"
fi
