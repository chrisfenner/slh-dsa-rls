#!/bin/sh

# Script to generate some suggested parameter sets for SLH-DSA

set -e

# 2^20 for firmware signing

go run ./cmd/slushfind \
    --name_prefix=rls128fw \
    --target_security_level=128 \
    --min_sig_count=20 \
    --max_sig_size=4000 \
    --min_sig_hashes=900000000 \
    --max_sig_hashes=1800000000 \
    --max_verify_hashes=1000 \
    --fallback_security_level=112 \
    --eval_sig_size=.5 \
    --eval_sig_hashes=0 \
    --eval_verify_hashes=0.5 \
    --table_format=markdown \

echo

go run ./cmd/slushfind \
    --name_prefix=rls192fw \
    --target_security_level=192 \
    --min_sig_count=20 \
    --max_sig_size=7600 \
    --min_sig_hashes=900000000 \
    --max_sig_hashes=1800000000 \
    --max_verify_hashes=1000 \
    --fallback_security_level=128 \
    --eval_sig_size=.5 \
    --eval_sig_hashes=0 \
    --eval_verify_hashes=0.5 \
    --table_format=markdown \

echo

go run ./cmd/slushfind \
    --name_prefix=rls256fw \
    --target_security_level=256 \
    --min_sig_count=20 \
    --max_sig_size=14000 \
    --min_sig_hashes=900000000 \
    --max_sig_hashes=1800000000 \
    --max_verify_hashes=1000 \
    --fallback_security_level=192 \
    --eval_sig_size=.5 \
    --eval_sig_hashes=0 \
    --eval_verify_hashes=0.5 \
    --table_format=markdown \

echo

# 2^24 for a single combined fw/sw parameter set that safely can be used once
# per minute for 30 years

go run ./cmd/slushfind \
    --name_prefix=rls128c \
    --target_security_level=128 \
    --min_sig_count=24 \
    --max_sig_size=4096 \
    --min_sig_hashes=900000000 \
    --max_sig_hashes=2000000000 \
    --max_verify_hashes=1000 \
    --fallback_security_level=112 \
    --eval_sig_size=0.5 \
    --eval_sig_hashes=0 \
    --eval_verify_hashes=0.5 \
    --table_format=markdown \

echo

go run ./cmd/slushfind \
    --name_prefix=rls192c \
    --target_security_level=192 \
    --min_sig_count=24 \
    --max_sig_size=8192 \
    --min_sig_hashes=900000000 \
    --max_sig_hashes=2000000000 \
    --max_verify_hashes=1000 \
    --fallback_security_level=128 \
    --eval_sig_size=0.5 \
    --eval_sig_hashes=0 \
    --eval_verify_hashes=0.5 \
    --table_format=markdown \

echo

go run ./cmd/slushfind \
    --name_prefix=rls256c \
    --target_security_level=256 \
    --min_sig_count=24 \
    --max_sig_size=16384 \
    --min_sig_hashes=900000000 \
    --max_sig_hashes=2000000000 \
    --max_verify_hashes=1000 \
    --fallback_security_level=192 \
    --eval_sig_size=0.5 \
    --eval_sig_hashes=0 \
    --eval_verify_hashes=0.5 \
    --table_format=markdown \

echo

# 2^30 for software signing

go run ./cmd/slushfind \
    --name_prefix=rls128sw \
    --target_security_level=128 \
    --min_sig_count=30 \
    --max_sig_size=5000 \
    --min_sig_hashes=0 \
    --max_sig_hashes=100000000 \
    --max_verify_hashes=20000 \
    --fallback_security_level=112 \
    --eval_sig_size=1.0 \
    --eval_sig_hashes=0 \
    --eval_verify_hashes=0 \
    --table_format=markdown \

echo

go run ./cmd/slushfind \
    --name_prefix=rls192sw \
    --target_security_level=192 \
    --min_sig_count=30 \
    --max_sig_size=10000 \
    --min_sig_hashes=0 \
    --max_sig_hashes=100000000 \
    --max_verify_hashes=20000 \
    --fallback_security_level=128 \
    --eval_sig_size=1.0 \
    --eval_sig_hashes=0 \
    --eval_verify_hashes=0 \
    --table_format=markdown \

echo

go run ./cmd/slushfind \
    --name_prefix=rls256sw \
    --target_security_level=256 \
    --min_sig_count=30 \
    --max_sig_size=16000 \
    --min_sig_hashes=0 \
    --max_sig_hashes=100000000 \
    --max_verify_hashes=20000 \
    --fallback_security_level=192 \
    --eval_sig_size=1.0 \
    --eval_sig_hashes=0 \
    --eval_verify_hashes=0 \
    --table_format=markdown \
