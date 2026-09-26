@echo off
cd /d "%~dp0"
echo ============================================================
echo   PhantomTrace - Building silent Windows agent (.exe)
echo ============================================================
echo.

echo [1/4] Killing any running PhantomTraceAgent.exe...
taskkill /F /IM PhantomTraceAgent.exe 1>nul 2>nul
REM Give Windows a moment to release file handles
timeout /t 3 /nobreak >nul
echo   done.
echo.

echo [2/4] Installing build tools and dependencies...
python -m pip install --upgrade pyinstaller pywin32 opencv-python pillow pycaw comtypes cryptography requests
echo.

echo [3/4] Cleaning previous build...
rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul
REM Force-remove a stale locked .exe if the rmdir left one behind
del /f /q dist\PhantomTraceAgent.exe 2>nul
echo.

echo [4/4] Building (this can take a few minutes)...
python -m PyInstaller --clean --noconfirm PhantomTraceAgent.spec
set PYINSTALLER_EXIT=%ERRORLEVEL%
echo.

if not %PYINSTALLER_EXIT%==0 (
  echo ############################################################
  echo   BUILD FAILED  (PyInstaller exit code: %PYINSTALLER_EXIT%)
  echo   Scroll up and copy the red error text.
  echo   Common cause: the old .exe is still locked - close any
  echo   Explorer/CMD/popup that might be holding it, then rerun.
  echo ############################################################
  pause
  exit /b %PYINSTALLER_EXIT%
)

if exist "dist\PhantomTraceAgent.exe" (
  echo ============================================================
  echo   BUILD OK  ^-^>  dist\PhantomTraceAgent.exe
  echo   Next: run  install.bat  as Administrator (production).
  echo ============================================================
) else (
  echo ############################################################
  echo   PyInstaller exited 0 but no .exe was produced.
  echo   Check the log above - something silently went wrong.
  echo ############################################################
)
pause
