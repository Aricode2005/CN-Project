@echo off
setlocal
REM ============================================================================
REM   CN Lab project: start EVERYTHING with one double-click.
REM
REM     run_all.bat          start all labs, each in its own window, and open the dashboards
REM     run_all.bat stop     stop every lab started by this script
REM     run_all.bat nobrowser   start everything but don't open browser tabs
REM
REM   The Main Project already contains ARP + DHCP + Telnet (with the HA cluster
REM   on 2330, RADIUS and group chat), so the separate ARP, DHCP and Telnet labs
REM   are NOT started: they would use the same ports.
REM ============================================================================
cd /d "%~dp0"

if /i "%~1"=="stop" goto :stop
set "NOBROWSER="
if /i "%~1"=="nobrowser" set "NOBROWSER=1"

where javac >nul 2>&1
if errorlevel 1 (
    echo  javac not found. Install a JDK 11+ and make sure it is on PATH.
    pause
    exit /b 1
)

REM ---- refuse to start twice (a lab is already holding its port)
netstat -ano | findstr /r /c:":8089 .*LISTENING" /c:":8083 .*LISTENING" /c:":8081 .*LISTENING" >nul
if not errorlevel 1 (
    echo  Some labs are already running ^(port 8081, 8083 or 8089 is busy^).
    echo  Run "run_all.bat stop" first, or close the old windows.
    pause
    exit /b 1
)

echo ============================================================================
echo   Starting all CN Lab modules (each opens in its own window)
echo ============================================================================

call :launch "MainProject" "Main Project (ARP+DHCP+Telnet)"
call :launch "Mail"        "Mail"
call :launch "DNS"         "DNS"
call :launch "RARP-BOOTP"  "RARP-BOOTP"
call :launch "FTP"         "FTP"
call :launch "HTTP"        "HTTP"
call :launch "Routing"     "Routing"

echo.
echo  Waiting for the dashboards to come up (compiling first time can take ~30 s)...
call :waitport 8089 90
call :waitport 8088 60

echo.
if not defined NOBROWSER (
    echo  Opening the dashboards in your browser...
    for %%P in (8089 8081 8080 8082 8083 8084 8085 8086 8087 8088) do start "" "http://localhost:%%P"
)

echo.
echo ============================================================================
echo   Main project (story) ..... http://localhost:8089   ^<-- start here
echo   Telnet dashboard ......... http://localhost:8081   (chapters 08-11: cluster, RADIUS, LINEMODE, chat)
echo   DHCP dashboard ........... http://localhost:8080
echo   ARP dashboard ............ http://localhost:8082
echo   Mail ..................... http://localhost:8083
echo   DNS ...................... http://localhost:8084
echo   RARP-BOOTP ............... http://localhost:8085
echo   FTP ...................... http://localhost:8086
echo   HTTP ..................... http://localhost:8087
echo   Routing .................. http://localhost:8088
echo.
echo   Laptop B:  telnet ^<this PC's IP^> 2325   (main project, crosses the simulated LAN)
echo              telnet ^<this PC's IP^> 2330   (Telnet extras: cluster, RADIUS, chat)
for /f "tokens=2 delims=:" %%I in ('ipconfig ^| findstr /c:"IPv4 Address"') do echo              this PC's IP:%%I
echo.
echo   To stop everything:  run_all.bat stop
echo ============================================================================
pause
exit /b 0

REM ---------------------------------------------------------------- helpers
:launch
REM %1 = folder, %2 = window title. The window stays open so errors stay visible.
if not exist "%~1\run.bat" (
    echo  [skip] %~1 has no run.bat
    exit /b 0
)
echo  starting %~2 ...
start "CNLAB %~2" /min /d "%~dp0%~1" cmd /k "title CNLAB %~2 & call "%~dp0%~1\run.bat""
exit /b 0

:waitport
REM %1 = port, %2 = seconds to wait at most
set /a _n=0
:waitloop
netstat -ano | findstr /r /c:":%1 .*LISTENING" >nul
if not errorlevel 1 exit /b 0
set /a _n+=1
if %_n% geq %2 (
    echo  [warn] nothing on port %1 after %2 s - check its window for errors
    exit /b 0
)
"%SystemRoot%\System32\timeout.exe" /t 1 /nobreak >nul
goto :waitloop

:stop
echo  Stopping every CN Lab window...
taskkill /t /f /fi "WINDOWTITLE eq CNLAB*" >nul 2>&1
echo  Done.
exit /b 0
