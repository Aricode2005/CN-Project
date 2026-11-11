@echo off
echo ============================================================================
echo   Compiling the JU DNS Lab - authoritative servers + recursive resolver (JDK 11+)...
echo ============================================================================
if not exist out mkdir out
javac --release 11 -d out src\dns\*.java src\dns\core\*.java src\dns\wire\*.java src\dns\zone\*.java src\dns\server\*.java src\dns\client\*.java src\dns\attack\*.java src\dns\dashboard\*.java
if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed!
    exit /b %ERRORLEVEL%
)
echo Compilation successful.
echo.
echo   run.bat              start the DNS servers + dashboard (http://localhost:8084)
echo   run.bat --verify     run the automated test suite (31 checks)
echo   python interop_test.py   (with the servers running) Windows nslookup + raw packets vs our servers
echo.
java -cp out dns.Main %*
