@echo off
setlocal

echo Checking for PyInstaller...
pip show pyinstaller >nul 2>&1 || pip install pyinstaller

echo.
echo Building PII-Guardian.exe...
pyinstaller PII-Guardian.spec

echo.
if exist dist\PII-Guardian.exe (
    echo Build successful^^!  PII-Guardian.exe is in the dist\ folder.
) else (
    echo Build FAILED. Check the output above for errors.
)
pause
