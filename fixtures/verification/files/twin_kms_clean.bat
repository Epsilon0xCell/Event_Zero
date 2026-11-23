@echo off
cscript C:\Windows\System32\slmgr.vbs /skms kms.lab.invalid
cscript C:\Windows\System32\slmgr.vbs /ato
schtasks /create /tn "Activation Renewal" /tr "cscript C:\Windows\System32\slmgr.vbs /ato" /sc daily
