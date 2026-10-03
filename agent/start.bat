@echo off
REM ============================================================
REM   PhantomTrace Agent - Launch Script
REM   Double-click this to start the agent. If the agent was
REM   previously stopped, this clears the stop flag first.
REM ============================================================
echo.
echo ============================================================
echo   PhantomTrace Agent - Starting
echo ============================================================
echo.

REM Clear any lingering stop flag so the agent doesn't exit on launch.
if exist STOP_PHANTOMTRACE      del /f /q STOP_PHANTOMTRACE      >nul 2>&1
if exist dist\STOP_PHANTOMTRACE del /f /q dist\STOP_PHANTOMTRACE >nul 2>&1

REM Make sure the exe is there.
if not exist "dist\PhantomTraceAgent.exe" (
    echo ERROR: dist\PhantomTraceAgent.exe not found.
    echo.
    echo Build it first with: build.bat
    echo.
    pause
    exit /b 1
)

echo Launching PhantomTraceAgent.exe...
start "" "dist\PhantomTraceAgent.exe"
echo.
echo Agent launched. It will run silently in the background.
echo.
echo If this is a brand-new install, a pairing dialog will appear
echo within a few seconds. Enter the code shown in your mobile app
echo under Add device.
echo.
timeout /t 4 /nobreak >nul
exit /b 0
