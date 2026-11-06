@echo off
echo ============================================================================
echo   Compiling Distributed DHCP Server Cluster in Java...
echo ============================================================================
if not exist out mkdir out
javac -d out src\dhcp\protocol\*.java src\dhcp\model\*.java src\dhcp\cluster\*.java src\dhcp\lb\*.java src\dhcp\client\*.java src\dhcp\dashboard\*.java src\dhcp\Main.java
if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed!
    exit /b %ERRORLEVEL%
)
echo Compilation successful! Starting cluster...
java -cp out dhcp.Main %*
