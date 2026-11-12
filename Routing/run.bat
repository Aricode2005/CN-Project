@echo off
echo ============================================================================
echo   Compiling the JU Routing Lab - Dijkstra, Bellman-Ford, RIP, OSPF, BGP...
echo ============================================================================
if not exist out mkdir out
javac --release 11 -d out src\route\*.java src\route\core\*.java src\route\wire\*.java src\route\net\*.java src\route\sim\*.java src\route\dashboard\*.java
if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed!
    exit /b %ERRORLEVEL%
)
echo Compilation successful.
echo.
echo   run.bat              start the dashboard (http://localhost:8088)
echo   run.bat --verify     run the automated test suite
echo   python interop_test.py   (with the lab running) an independent Python decoder checks our RIP / OSPF / BGP bytes
echo.
java -Djava.awt.headless=true -cp out route.Main %*
