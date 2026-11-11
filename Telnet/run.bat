@echo off
echo ============================================================================
echo   Compiling the Telnet Remote-Management Lab (pure Java, JDK 11+)...
echo ============================================================================
if not exist out mkdir out
javac --release 11 -d out src\telnet\*.java src\telnet\core\*.java src\telnet\protocol\*.java src\telnet\server\*.java src\telnet\tap\*.java src\telnet\client\*.java src\telnet\dashboard\*.java
if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed!
    exit /b %ERRORLEVEL%
)
echo Compilation successful.
echo.
echo   run.bat              start server + dashboard (http://localhost:8081)
echo   run.bat --verify     run the automated test suite
echo   run.bat client       console Telnet client via the wire tap (port 2324)
echo.
java -cp out telnet.Main %*
