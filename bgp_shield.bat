@echo off
title BGP-Shield: Sentinel Platform Control Center
setlocal enabledelayedexpansion
cd /d "%~dp0"

:: Handle command line arguments if provided
if "%1"=="start" goto :START_ALL
if "%1"=="stop" goto :STOP_ALL
if "%1"=="test" goto :RUN_TESTS

:MENU
cls
echo ======================================================
echo    BGP-Shield: Sentinel Platform Control Center
echo ======================================================
echo.
echo   [1] Start All Services (Local Native: Engine + Gateway + Console)
echo   [2] Stop All Services  (Clean Shutdown)
echo   [3] Run Automated Test Suite (Pytest)
echo   [4] Start Python Stream Engine Only (Port 8000 & UDP 2055)
echo   [5] Start Laravel 12 Gateway Only   (Port 8080)
echo   [6] Start React 19 Console Only     (Port 5173)
echo   [D] Run Full Platform with Docker Compose (Engine + Gateway + Nginx)
echo   [S] Stop Docker Compose Containers
echo   [0] Exit
echo.
echo ======================================================
set /p choice="Select an option: "

if /i "%choice%"=="1" goto :START_ALL
if /i "%choice%"=="2" goto :STOP_ALL
if /i "%choice%"=="3" goto :RUN_TESTS
if /i "%choice%"=="4" goto :START_ENGINE
if /i "%choice%"=="5" goto :START_BACKEND
if /i "%choice%"=="6" goto :START_FRONTEND
if /i "%choice%"=="D" goto :DOCKER_START
if /i "%choice%"=="S" goto :DOCKER_STOP
if "%choice%"=="0" goto :EXIT
echo Invalid selection. Please try again.
timeout /t 2 >nul
goto :MENU


:START_ALL
echo.
echo [*] Starting BGP-Shield Platform Services...
echo [1/3] Launching Python Stream Analytics Engine (Port 8000)...
start "BGP-Shield Engine" cmd /k "cd /d %~dp0engine && python run_engine.py"

echo [2/3] Launching Laravel 12 Incident Gateway (Port 8080)...
start "BGP-Shield Gateway" cmd /k "cd /d %~dp0backend && php artisan serve --port=8080"

echo [3/3] Launching React 19 + D3.js Visualization Console (Port 5173)...
start "BGP-Shield Console" cmd /k "cd /d %~dp0frontend && npm.cmd run dev -- --port 5173"

timeout /t 3 /nobreak >nul
echo Opening BGP-Shield Console in default browser...
start http://localhost:5173/

echo.
echo ======================================================
echo   BGP-Shield is up and running!
echo   - Web Console:      http://localhost:5173/
echo   - Stream Engine:    http://127.0.0.1:8000/
echo   - Incident Gateway: http://127.0.0.1:8080/
echo ======================================================
echo.
pause
goto :MENU

:STOP_ALL
echo.
echo [*] Stopping all BGP-Shield services on ports 8000, 8080, 5173...
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8000, 8080, 5173 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue; Write-Host ('Stopped process on port ' + $_.LocalPort + ' (PID: ' + $_.OwningProcess + ')') }"
echo [*] All BGP-Shield services stopped.
echo.
pause
goto :MENU

:RUN_TESTS
echo.
echo [*] Running BGP-Shield automated pytest suite...
python -m pytest engine/tests
echo.
pause
goto :MENU

:START_ENGINE
echo.
echo [*] Starting Python Stream Analytics Engine on port 8000...
start "BGP-Shield Engine" cmd /k "cd /d %~dp0engine && python run_engine.py"
goto :MENU

:START_BACKEND
echo.
echo [*] Starting Laravel 12 Incident Gateway on port 8080...
start "BGP-Shield Gateway" cmd /k "cd /d %~dp0backend && php artisan serve --port=8080"
goto :MENU

:START_FRONTEND
echo.
echo [*] Starting React 19 + D3.js Console on port 5173...
start "BGP-Shield Console" cmd /k "cd /d %~dp0frontend && npm.cmd run dev -- --port 5173"
goto :MENU

:DOCKER_START
echo.
echo [*] Building and launching BGP-Shield via Docker Compose...
docker compose up --build -d
echo.
echo [*] Container status:
docker compose ps
echo.
echo BGP-Shield Docker stack is running!
echo Access the console at: http://localhost:5173/
echo.
pause
goto :MENU

:DOCKER_STOP
echo.
echo [*] Stopping BGP-Shield Docker Compose containers...
docker compose down
echo [*] Containers stopped.
echo.
pause
goto :MENU

:EXIT
echo Exiting BGP-Shield Control Center.
exit /b 0

