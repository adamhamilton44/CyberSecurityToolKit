#!/usr/bin/env bash
# Rebuild both maintained entry points from an explicit build environment.
set -euo pipefail
build_python=${1:?Usage: build_engagement_reporting.sh /absolute/build-venv/bin/python}
[[ "$build_python" == /* ]] || { echo 'Use an absolute build Python.' >&2; exit 2; }
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
upx -9 "$stage/dist/Etc_engagement"
install -m 755 "$stage/dist/Etc_engagement" "$root/scripts/bin/Etc_engagement"
bash "$root/scripts/source/reporting/build_binary.sh" "$build_python" "$root/scripts/bin"
