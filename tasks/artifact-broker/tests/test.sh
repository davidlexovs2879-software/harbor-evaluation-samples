#!/bin/sh
set -eu
mkdir -p /logs/verifier
printf '0\n' > /logs/verifier/reward.txt
chmod 700 /tests
python /tests/verify.py
