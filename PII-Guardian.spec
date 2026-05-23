# PII-Guardian.spec  —  PyInstaller 6.x single-file build
from PyInstaller.utils.hooks import collect_all

# ── Accumulate data files, binaries and hidden imports ─────────────────────────
datas        = [('app.py', '.')]
binaries     = []
hiddenimports = [
    # presidio loads recognisers dynamically
    'presidio_analyzer.predefined_recognizers',
    'presidio_analyzer.predefined_recognizers.spacy_recognizer',
    'presidio_analyzer.predefined_recognizers.pattern_recognizer',
    # spaCy English pipeline
    'spacy.lang.en',
    'spacy.lang.en.stop_words',
    # streamlit entrypoints
    'streamlit.web.cli',
    'streamlit.runtime.scriptrunner.magic_funcs',
]

for pkg in [
    # UI / server
    'streamlit', 'altair', 'pydeck', 'pyarrow',
    # PII detection
    'presidio_analyzer', 'presidio_anonymizer',
    # NLP stack
    'spacy', 'en_core_web_lg',
    'thinc', 'cymem', 'murmurhash', 'preshed', 'blis', 'srsly', 'catalogue',
    'weasel', 'confection', 'langcodes',
    # fake data & tabular
    'faker', 'pandas', 'openpyxl',
]:
    d, b, h = collect_all(pkg)
    datas        += d
    binaries     += b
    hiddenimports += h

# ── Analysis ───────────────────────────────────────────────────────────────────
a = Analysis(
    ['launcher.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['matplotlib', 'scipy', 'IPython', 'tkinter', 'unittest'],
    noarchive=False,
)

# ── PYZ archive ────────────────────────────────────────────────────────────────
pyz = PYZ(a.pure)

# ── Single-file EXE ────────────────────────────────────────────────────────────
# Passing a.binaries and a.datas directly into EXE (not COLLECT) produces --onefile.
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='PII-Guardian',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,          # keep console so users can see the Streamlit URL
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
