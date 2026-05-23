@echo off
setlocal

echo Checking for PyInstaller...
pip show pyinstaller >nul 2>&1 || pip install pyinstaller

echo.
echo Building PII-Guardian.exe...
pyinstaller --onefile --name PII-Guardian ^
  --collect-all streamlit ^
  --collect-all altair ^
  --collect-all presidio_analyzer ^
  --collect-all presidio_anonymizer ^
  --collect-all spacy ^
  --collect-all en_core_web_lg ^
  --collect-all faker ^
  --collect-all pandas ^
  --collect-all openpyxl ^
  --hidden-import presidio_analyzer.predefined_recognizers ^
  --hidden-import presidio_analyzer.predefined_recognizers.spacy_recognizer ^
  --hidden-import spacy.lang.en ^
  --hidden-import thinc ^
  --hidden-import cymem ^
  --hidden-import murmurhash ^
  --hidden-import preshed ^
  --add-data "app.py;." ^
  launcher.py

echo.
if exist dist\PII-Guardian.exe (
    echo Build successful^^!  PII-Guardian.exe is in the dist\ folder.
) else (
    echo Build FAILED. Check the output above for errors.
)
pause
