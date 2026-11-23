| Fixture | Family | Tier | Expected | Issued | Case | Proof exhibited | Result |
|---|---|---|---|---|---|---|---|
| stealer_config.py | stealer | 1 | YES/PROVEN | YES/PROVEN | YES | family-stealer-config | PASS |
| stealer_chain.py | stealer | 1 | YES/PROVEN | YES/PROVEN | YES | stealer | PASS |
| rat_dispatcher.py | rat | 1 | YES/PROVEN | YES/PROVEN | YES | family-rat-dispatcher | PASS |
| ransomware.py | ransomware | 1 | YES/PROVEN | YES/PROVEN | YES | ransomware | PASS |
| miner_hidden.py | miner | 1 | YES/PROVEN | YES/PROVEN | YES | miner | PASS |
| loader_inject.py | loader | 1 | YES/PROVEN | YES/PROVEN | YES | download-and-execute | PASS |
| loader_dead_drop.py | loader | 1 | YES/PROVEN | YES/PROVEN | YES | download-and-execute | PASS |
| server_keyed.py | server-keyed | 1 | YES/PROVEN | YES/PROVEN | YES | download-and-execute | PASS |
| botnet_flood.py | botnet | 1 | YES/PROVEN | YES/PROVEN | YES | family-botnet-ddos | PASS |
| bootkit.py | bootkit | 1 | YES/PROVEN | YES/PROVEN | YES | family-bootkit-staging | PASS |
| keylogger_stash.py | keylogger | 1 | YES/PROVEN | YES/PROVEN | YES | family-keylogger-stash | PASS |
| banking_targets.py | banking | 1 | YES/PROVEN | YES/PROVEN | YES | family-banking-targets | PASS |
| proxy_operator.py | proxy | 1 | YES/PROVEN | YES/PROVEN | YES | persistence-plus-c2 | PASS |
| ppi_callback.py | ppi | 1 | YES/PROVEN | YES/PROVEN | YES | family-ppi-callback | PASS |
| hijacker.py | adware-hijacker | 1 | YES/PROVEN | YES/PROVEN | YES | persistence-plus-c2 | PASS |
| beacon_config.bin | beacon | 1 | YES/PROVEN | YES/PROVEN | YES | family-beacon-config | PASS |
| wiper.py | wiper | 1 | YES/PROVEN | YES/PROVEN | YES | family-wiper | PASS |
| fileless_decodable.py | fileless | 1 | YES/PROVEN | YES/PROVEN | YES | family-fileless-registry-blob | PASS |
| script_bad.bat | malicious-script | 1 | YES/PROVEN | YES/PROVEN | YES | download-and-execute | PASS |
| sideload_folder | sideload | 1 | YES/PROVEN | YES/PROVEN | YES | dll-sideload-triad | PASS |
| twin_password_manager.py | stealer-fp-twin | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |
| twin_miner_disclosed.py | miner-fp-twin | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |
| twin_backup_encryptor.py | ransomware-fp-twin | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |
| twin_kms_clean.bat | script-fp-twin | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |
| twin_proxy_disclosed.py | proxy-fp-twin | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |
| twin_keygen.py | keygen-control | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |
| twin_capture_tool.py | keylogger-fp-twin | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |
| twin_xmrig_alone.py | miner-presence-control | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |
| sideload_genuine | sideload-fp-twin | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |
| open_rootkit.sys | rootkit | 2 | YES/UNACCOUNTED | YES/UNACCOUNTED | OPEN | none | PASS |
| open_logic_bomb.py | logic-bomb | 2 | YES/UNACCOUNTED | YES/UNACCOUNTED | OPEN | none | PASS |
| open_fileless_blob.py | fileless | 2 | YES/UNACCOUNTED | YES/UNACCOUNTED | OPEN | none | PASS |
| open_password_archive.zip | archive | 2 | YES/UNACCOUNTED | YES/UNACCOUNTED | OPEN | none | PASS |
| surprise_updater.bat | surprise-loader-script | 1 | YES/PROVEN | YES/PROVEN | YES | download-and-execute | PASS |
| surprise_shadow.bat | surprise-anti-recovery-script | 1 | YES/PROVEN | YES/PROVEN | YES | download-and-execute | PASS |
| surprise_dll_stealer | surprise-stealer-in-dll | 1 | YES/PROVEN | YES/PROVEN | YES | family-stealer-config | PASS |
| surprise_banking_article.txt | surprise-banking-fp | 1 | NO/ACCOUNTED | NO/ACCOUNTED | NO | none | PASS |

Corpus ledger root (hash of the per-fixture ledger roots): b5e851ff1ba166a2083e15681256ec06a5af9603aba364b7b9f6fd1348cc1f4b
Result: PASS (37 entries, 0 mismatches, 0 unexpected Tier-1 unaccounted, 0 false NO, 0 determinism failures)
