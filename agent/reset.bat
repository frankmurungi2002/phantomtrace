@echo off
REM ============================================================
REM   PhantomTrace Agent - Reset Script
REM   Double-click this to wipe the agent's local pairing state
REM   so your next PhantomTraceAgent.exe launch asks for a code.
REM ============================================================
echo.
echo ============================================================
echo   PhantomTrace Agent - Resetting local state
echo ============================================================
echo.

REM 1. Stop any running agent + watchdog first.
echo [1/5] Stopping any running agent + watchdog...
if exist dist\STOP_PHANTOMTRACE del /f /q dist\STOP_PHANTOMTRACE >nul 2>&1
echo stop > STOP_PHANTOMTRACE
echo stop > dist\STOP_PHANTOMTRACE
timeout /t 6 /nobreak >nul
taskkill /f /im PhantomTraceAgent.exe >nul 2>&1
echo   done.

REM 2. Delete the stop flags so the next launch isn't blocked.
echo [2/5] Removing stop flags...
if exist STOP_PHANTOMTRACE del /f /q STOP_PHANTOMTRACE >nul 2>&1
if exist dist\STOP_PHANTOMTRACE del /f /q dist\STOP_PHANTOMTRACE >nul 2>&1
echo   done.

REM 3. Delete device.json so pairing dialog shows next launch.
echo [3/5] Removing device.json...
if exist dist\device.json del /f /q dist\device.json >nul 2>&1
if exist device.json      del /f /q device.json      >nul 2>&1
echo   done.

REM 4. Delete the registry backup so persistence can't restore device.json.
echo [4/5] Removing registry backup (HKCU\Software\PhantomTrace)...
reg delete "HKCU\Software\PhantomTrace" /f >nul 2>&1
echo   done.

REM 5. Delete heartbeat + trigger state files (optional, but keeps dist clean).
echo [5/5] Removing heartbeat + trigger state files...
if exist dist\agent_alive.txt    del /f /q dist\agent_alive.txt    >nul 2>&1
if exist dist\watchdog_alive.txt del /f /q dist\watchdog_alive.txt >nul 2>&1
if exist dist\trigger_state.json del /f /q dist\trigger_state.json >nul 2>&1
echo   done.

echo.
echo ============================================================
echo   Reset complete.
echo.
echo   Next step: double-click dist\PhantomTraceAgent.exe
echo   The pairing dialog will appear. Enter a code from your
echo   PhantomTrace mobile app under Add device.
echo ============================================================
echo.
pause
