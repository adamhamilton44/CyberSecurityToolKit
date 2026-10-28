#!/usr/bin/env bash
# Run from the isolated source folder using an explicitly selected build Python.
set -euo pipefail
build_python=${1:?Usage: build_binary.sh /absolute/build-venv/bin/python /absolute/output/directory}
destination=${2:?Specify an output directory}
[[ "$build_python" == /* && "$destination" == /* ]] || { echo 'Use absolute paths.' >&2; exit 2; }
here=$(cd -- "$(dirname -- "$0")" && pwd -P)
mkdir -p -- "$destination"
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
# python-docx resolves parts/../templates through the real filesystem.
# PyInstaller's module archive alone does not create the intermediate directory.
: > "$stage/docx-parts-directory.marker"
"$build_python" -m PyInstaller --clean --noconfirm --onefile --strip \
    --name cstk-reporting --paths "$here" --collect-data docx \
    --add-data "$stage/docx-parts-directory.marker:docx/parts" \
    --distpath "$stage/dist" --workpath "$stage/build" --specpath "$stage/spec" \
    "$here/entrypoint.py"
upx -9 "$stage/dist/cstk-reporting"
install -m 755 "$stage/dist/cstk-reporting" "$destination/cstk-reporting"
