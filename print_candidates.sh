#!/bin/sh

# Script to generate some suggested parameter sets for SLH-DSA

set -e

# 2^24 for a single code signing set, tuned for verification time
# These retain full strength at one signature per minute for 30 years,
# and if the signer does not cache the hypertree, they are not likely to be
# physically able to exceed that on typical HSM hardware in 2025

go run ./cmd/slushfind \
    --name_prefix=rls128cs \
    --target_security_level=128 \
    --overuse_security_level=112 \
    --min_sig_count=24 \
    --max_sig_size=4096 \
    --max_sig_hashes=3000000000 \
    --max_verify_hashes=1000 \
    --eval_sig_size=0.5 \
    --eval_sig_hashes=0 \
    --eval_verify_hashes=0.5 \
    --table_format=markdown \

echo

go run ./cmd/slushfind \
    --name_prefix=rls192cs \
    --target_security_level=192 \
    --overuse_security_level=128 \
    --min_sig_count=24 \
    --max_sig_size=8192 \
    --max_sig_hashes=3000000000 \
    --max_verify_hashes=1000 \
    --eval_sig_size=0.5 \
    --eval_sig_hashes=0 \
    --eval_verify_hashes=0.5 \
    --table_format=markdown \

echo

go run ./cmd/slushfind \
    --name_prefix=rls256cs \
    --target_security_level=256 \
    --overuse_security_level=192 \
    --min_sig_count=24 \
    --max_sig_size=16384 \
    --max_sig_hashes=3000000000 \
    --max_verify_hashes=1000 \
    --eval_sig_size=0.5 \
    --eval_sig_hashes=0 \
    --eval_verify_hashes=0.5 \
    --table_format=markdown \

echo

# 2^30 (with "probably good enough" security at 2^40 signatures), tuned for size
# These retain full strength at one signature per second for 30 years, and
# retain "good enough" strength at one signature per millisecond for 30 years

go run ./cmd/slushfind \
    --name_prefix=rls128gp \
    --target_security_level=128 \
    --overuse_security_level=112 \
    --min_sig_count=30 \
    --min_sig_count_at_overuse=40 \
    --max_sig_size=4096 \
    --max_sig_hashes=3000000000 \
    --max_verify_hashes=100000 \
    --eval_sig_size=1.0 \
    --eval_sig_hashes=0 \
    --eval_verify_hashes=0 \
    --table_format=markdown \

echo

go run ./cmd/slushfind \
    --name_prefix=rls192gp \
    --target_security_level=192 \
    --overuse_security_level=128 \
    --min_sig_count=30 \
    --min_sig_count_at_overuse=40 \
    --max_sig_size=8192 \
    --max_sig_hashes=3000000000 \
    --max_verify_hashes=100000 \
    --eval_sig_size=1.0 \
    --eval_sig_hashes=0 \
    --eval_verify_hashes=0 \
    --table_format=markdown \

echo

go run ./cmd/slushfind \
    --name_prefix=rls256gp \
    --target_security_level=256 \
    --overuse_security_level=192 \
    --min_sig_count=30 \
    --min_sig_count_at_overuse=40 \
    --max_sig_size=16384 \
    --max_sig_hashes=3000000000 \
    --max_verify_hashes=100000 \
    --eval_sig_size=1.0 \
    --eval_sig_hashes=0 \
    --eval_verify_hashes=0 \
    --table_format=markdown \

echo
