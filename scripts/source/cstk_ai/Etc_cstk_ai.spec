# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

source = Path(SPEC).resolve().parent

a = Analysis(
    [str(source / "cstk_ai.py")],
    pathex=[str(source)],
    binaries=[],
    datas=[
        (str(source / "cstk_engagement.py"), "."),
        (str(source / "engagement_scoping_cheat_sheet.md"), "."),
        (str(source / "engagement_form_template.json"), "."),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # These optional developer, notebook, GUI, plotting, and test stacks are
    # discoverable in the build environment but are not used by this TUI.
    excludes=[
        "IPython", "PIL", "PyQt5", "PyQt6", "PySide6", "_tkinter",
        "astroid", "bcrypt", "cryptography", "gi", "jedi", "jsonschema",
        "matplotlib", "nbformat", "numpy", "parso", "psutil", "py",
        "pygame", "pytest", "tkinter",
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="Etc_cstk_ai",
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
