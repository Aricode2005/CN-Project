@echo off
echo ============================================================================
echo   Compiling the JU FTP Lab - RFC 959 server + client (pure Java, JDK 11+)...
echo ============================================================================
if not exist out mkdir out
javac --release 11 -d out src\ftp\*.java src\ftp\core\*.java src\ftp\server\*.java src\ftp\client\*.java src\ftp\tap\*.java src\ftp\dashboard\*.java
if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed!
    exit /b %ERRORLEVEL%
)
echo Compilation successful.
echo.
echo   run.bat              start the FTP server, wire tap + dashboard (http://localhost:8086)
echo   run.bat --verify     run the automated test suite (31 checks)
echo   python interop_test.py   (with the lab running) Python ftplib + Windows ftp.exe vs our server
echo.
java -Djava.awt.headless=true -cp out ftp.Main %*
