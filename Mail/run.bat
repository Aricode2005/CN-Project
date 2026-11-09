@echo off
echo ============================================================================
echo   Compiling the JU Mail Lab - SMTP / POP3 / IMAP4 (pure Java, JDK 11+)...
echo ============================================================================
if not exist out mkdir out
javac --release 11 -d out src\mail\*.java src\mail\core\*.java src\mail\mime\*.java src\mail\store\*.java src\mail\server\*.java src\mail\client\*.java src\mail\dashboard\*.java
if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed!
    exit /b %ERRORLEVEL%
)
echo Compilation successful.
echo.
echo   run.bat              start the mail servers + dashboard (http://localhost:8083)
echo   run.bat --verify     run the automated test suite (our clients vs our servers)
echo   python interop_test.py   (with the servers running) Python's own mail clients vs our servers
echo.
java -cp out mail.Main %*
