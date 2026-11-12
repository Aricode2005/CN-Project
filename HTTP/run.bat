@echo off
echo ============================================================================
echo   Compiling the JU HTTP Lab - HTTP/1.1 server, client, WAN link + caching proxy...
echo ============================================================================
if not exist out mkdir out
javac --release 11 -d out src\http\*.java src\http\core\*.java src\http\server\*.java src\http\client\*.java src\http\link\*.java src\http\proxy\*.java src\http\dashboard\*.java
if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed!
    exit /b %ERRORLEVEL%
)
echo Compilation successful.
echo.
echo   run.bat              start the web server, WAN link, proxy + dashboard (http://localhost:8087)
echo   run.bat --verify     run the automated test suite
echo   python interop_test.py   (with the lab running) Python http.client/urllib + curl vs our server and proxy
echo.
java -Djava.awt.headless=true -cp out http.Main %*
