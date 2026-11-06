@echo off
echo ============================================================================
echo   Compiling Address Resolution Protocol (ARP) Lab (pure Java, JDK 11+)...
echo ============================================================================
if not exist out mkdir out

REM Try standard javac or search known JDK locations
where javac >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    if defined JAVA_HOME (
        set "PATH=%JAVA_HOME%\bin;%PATH%"
    )
)

javac --release 11 -d out src\arp\core\*.java src\arp\model\*.java src\arp\protocol\*.java src\arp\security\*.java src\arp\network\*.java src\arp\dashboard\*.java src\arp\*.java
if %ERRORLEVEL% NEQ 0 (
    REM Fallback to standard javac without --release flag if older/newer compiler
    javac -d out src\arp\core\*.java src\arp\model\*.java src\arp\protocol\*.java src\arp\security\*.java src\arp\network\*.java src\arp\dashboard\*.java src\arp\*.java
    if %ERRORLEVEL% NEQ 0 (
        echo Compilation failed! Please ensure JDK 11+ is installed and on your PATH.
        exit /b %ERRORLEVEL%
    )
)

echo Compilation successful!
echo.
echo   run.bat              start ARP lab + dashboard (http://localhost:8082)
echo   run.bat --verify     run automated RFC 826 verification test suite
echo.
java -cp out arp.Main %*
