@echo off
setlocal
echo ============================================================================
echo   Compiling Address Resolution Protocol (ARP) Lab (pure Java, JDK 11+)...
echo ============================================================================
if not exist out mkdir out

REM Detect working JDK: check JAVA_HOME or probe installed JDK directories
set "FOUND_JDK="
if defined JAVA_HOME (
    if exist "%JAVA_HOME%\bin\javac.exe" set "FOUND_JDK=%JAVA_HOME%"
)
if not defined FOUND_JDK (
    if exist "C:\Program Files\Java\latest\jdk-27\bin\javac.exe" (
        set "FOUND_JDK=C:\Program Files\Java\latest\jdk-27"
    )
)
if not defined FOUND_JDK (
    for /d %%D in ("C:\Program Files\Java\latest\jdk*" "C:\Program Files\Java\jdk*" "C:\Program Files\Eclipse Adoptium\jdk*" "C:\Program Files\Amazon Corretto\jdk*") do (
        if exist "%%D\bin\javac.exe" set "FOUND_JDK=%%D"
    )
)

if defined FOUND_JDK (
    set "PATH=%FOUND_JDK%\bin;%PATH%"
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
echo   run.bat                  start ARP lab + dashboard (http://localhost:8082)
echo   run.bat --verify         run automated RFC 826 / 5227 / 903 verification test suite (50+ checks)
echo   python interop_test.py   (with server running) automated HTTP, Cisco CLI and PCAP verification
echo.
java -cp out arp.Main %*
