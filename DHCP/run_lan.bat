@echo off
echo ============================================================================
echo   Compiling & Starting Distributed DHCP Server in DIRECT LAN MODE (Port 67)
echo   NOTE: Run this terminal as Administrator so Windows allows UDP Port 67!
echo ============================================================================
if not exist out mkdir out
javac -d out src\dhcp\protocol\*.java src\dhcp\model\*.java src\dhcp\cluster\*.java src\dhcp\lb\*.java src\dhcp\client\*.java src\dhcp\dashboard\*.java src\dhcp\Main.java
if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed!
    exit /b %ERRORLEVEL%
)
echo Starting Load Balancer on 0.0.0.0:67 (Broadcast -> 255.255.255.255:68)...
java -cp out dhcp.Main --lan %*
