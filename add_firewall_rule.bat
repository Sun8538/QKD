@echo off
:: Run this ONCE as Administrator to allow phones on WiFi to reach Flask on port 5000
netsh advfirewall firewall add rule name="Flask QKD Port 5000" dir=in action=allow protocol=TCP localport=5000
echo.
echo Done! Port 5000 is now open for inbound connections.
echo You can delete this file after running it.
pause
