#!/bin/sh
# The verification stage, run inside the network-disabled container
# (docker run --network none) by .github/workflows/verify.yml.
# Steps: prove egress is impossible (canary), build the synthetic
# corpus, run The Verdict over the whole corpus TWICE, and enforce
# the determinism gate (the two runs' ledger roots must be identical).
# All proof outputs land in /proof (a mounted volume): per-run
# results and roots, plus the corpus manifest hash.
set -e
cd /app
mkdir -p /proof/run1 /proof/run2
python fixtures/verification/egress_canary.py
python fixtures/verification/build_corpus.py
python fixtures/verification/run_verification.py --outdir /proof/run1
python fixtures/verification/run_verification.py --outdir /proof/run2
diff /proof/run1/roots.json /proof/run2/roots.json
echo "DETERMINISM GATE: PASS (two corpus runs produced identical ledger roots)"
sha256sum fixtures/verification/manifest.json > /proof/manifest.sha256
cat /proof/manifest.sha256
