@echo off
echo ============================================================================
echo   Compiling the CN Main Project - ARP + DHCP + Telnet as one campus LAN...
echo ============================================================================
if not exist out mkdir out
javac --release 11 -encoding UTF-8 -d out -sourcepath "..\ARP\src;..\DHCP\src;..\Telnet\src;src" src\campus\*.java
if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed!
    exit /b %ERRORLEVEL%
)
echo Compilation successful.
echo.
echo   run.bat              start the campus LAN: story at http://localhost:8089
echo   run.bat --verify     run the end-to-end checks (18)
echo   (stop the separate ARP / DHCP / Telnet labs first: they use the same ports)
echo.
java -Djava.awt.headless=true -cp out campus.Main %*
