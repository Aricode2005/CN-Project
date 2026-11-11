@echo off
echo ============================================================================
echo   Compiling the JU Bootstrap Lab - RARP + BOOTP (pure Java, JDK 11+)...
echo ============================================================================
if not exist out mkdir out
javac --release 11 -d out src\boot\*.java src\boot\core\*.java src\boot\rarp\*.java src\boot\bootp\*.java src\boot\dashboard\*.java
if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed!
    exit /b %ERRORLEVEL%
)
echo Compilation successful.
echo.
echo   run.bat              start the RARP LAN + BOOTP server/relay + dashboard (http://localhost:8085)
echo   run.bat --verify     run the automated test suite (19 checks)
echo   python interop_test.py   (with the lab running) a Python BOOTP client vs our server
echo.
java -cp out boot.Main %*
