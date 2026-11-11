@echo off
echo ============================================================================
echo   RESTORING NETWORK TO NORMAL AUTOMATIC DHCP MODE
echo   (Must be run as Administrator)
echo ============================================================================
echo 1. Resetting Wi-Fi IPv4 to 'Obtain an IP address automatically' (DHCP)...
netsh interface ip set address name="Wi-Fi" dhcp
echo 2. Resetting Wi-Fi DNS to 'Obtain DNS server address automatically'...
netsh interface ip set dns name="Wi-Fi" dhcp
echo 3. Removing temporary UDP Port 67 Firewall rule...
netsh advfirewall firewall delete rule name="Java DHCP Server Port 67" >nul 2>&1
echo 4. Renewing Wi-Fi IP address from your Router...
ipconfig /renew "Wi-Fi"
echo ============================================================================
echo   DONE! Your laptop Wi-Fi is back to normal automatic DHCP.
echo   REMINDER: Make sure 'Enable DHCP Server' is toggled back ON
echo             in your router admin page (http://192.168.1.1)!
echo ============================================================================
