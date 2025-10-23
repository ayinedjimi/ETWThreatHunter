@echo off
REM Compilation script for ETWThreatHunter
REM WinToolsSuite Serie 3 - Forensics Tool #24

echo ========================================
echo Building ETWThreatHunter
echo ========================================

cl.exe /nologo /W4 /EHsc /O2 /DUNICODE /D_UNICODE ^
    /Fe:ETWThreatHunter.exe ^
    ETWThreatHunter.cpp ^
    /link ^
    comctl32.lib shlwapi.lib advapi32.lib tdh.lib user32.lib gdi32.lib shell32.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Build successful!
    echo Executable: ETWThreatHunter.exe
    echo ========================================
    if exist ETWThreatHunter.obj del ETWThreatHunter.obj
) else (
    echo.
    echo ========================================
    echo Build FAILED!
    echo ========================================
    exit /b 1
)
