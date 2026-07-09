@echo off
chcp 65001 >nul
title NetAuto Maintainer - 人力採集 RAW DATA
cd /d "%~dp0"

echo ============================================================
echo   NetAuto Maintainer - 人力採集 RAW DATA
echo   適用：設備清單已確定（型號/IP/帳密齊全）時直接採集
echo   接下來會跳出視窗，請依序選擇「設備清單」與「輸出資料夾」
echo ============================================================
echo.

where py >nul 2>nul
if %errorlevel%==0 (
    py "%~dp0scripts\collect_gui.py"
) else (
    python "%~dp0scripts\collect_gui.py"
)

echo.
echo （採集流程結束，可關閉本視窗）
pause
