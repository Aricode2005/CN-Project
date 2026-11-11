@echo off
cd /d "%~dp0"
echo ============================================================================
echo   STEP 1: Setting Windows Wi-Fi Adapter to Static IP (192.168.1.41)
echo   (Must be run as Administrator)
echo ============================================================================
netsh interface ip set address name="Wi-Fi" static 192.168.1.41 255.255.255.0 192.168.1.1
netsh interface ip set dns name="Wi-Fi" static 8.8.8.8

echo ============================================================================
echo   STEP 2: Opening UDP Port 67/68 in Windows Firewall (All Profiles)
echo ============================================================================
netsh advfirewall firewall delete rule name="Java DHCP Server Port 67" >nul 2>&1
netsh advfirewall firewall add rule name="Java DHCP Server Port 67" dir=in action=allow protocol=UDP localport=67 profile=any remoteip=any
netsh advfirewall firewall add rule name="Java DHCP Server Port 67" dir=out action=allow protocol=UDP remoteport=68 profile=any remoteip=any

echo ============================================================================
echo   STEP 3: Starting Java Distributed DHCP Server on 192.168.1.x (Port 67)...
echo   When you press 'q' to quit, your Wi-Fi will automatically reset to DHCP!
echo ============================================================================
call .\run_lan.bat --subnet 192.168.1. --gateway 192.168.1.1 --dns 8.8.8.8

echo ============================================================================
echo   Auto-Restoring Windows Wi-Fi Adapter back to normal Automatic DHCP...
echo ============================================================================
call .\restore_normal_network.bat
