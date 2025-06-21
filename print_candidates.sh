#!/bin/sh

# Script to generate some suggested parameter sets for SLH-DSA

set -e

# 2^20 for firmware signing

go run ./cmd/slushfind \
    --name_prefix=rls-128-fw \
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
    --name_prefix=rls-192-fw \
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
    --name_prefix=rls-256-fw \
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

# 2^30 for software signing

go run ./cmd/slushfind \
    --name_prefix=rls-128-sw \
    --target_security_level=128 \
    --min_sig_count=30 \
    --max_sig_size=5000 \
    --min_sig_hashes=0 \
    --max_sig_hashes=100000000 \
    --max_verify_hashes=10000 \
    --fallback_security_level=112 \
    --eval_sig_size=1.0 \
    --eval_sig_hashes=0 \
    --eval_verify_hashes=0 \
    --table_format=markdown \

echo

go run ./cmd/slushfind \
    --name_prefix=rls-192-sw \
    --target_security_level=192 \
    --min_sig_count=30 \
    --max_sig_size=10000 \
    --min_sig_hashes=0 \
    --max_sig_hashes=100000000 \
    --max_verify_hashes=10000 \
    --fallback_security_level=128 \
    --eval_sig_size=1.0 \
    --eval_sig_hashes=0 \
    --eval_verify_hashes=0 \
    --table_format=markdown \

echo

go run ./cmd/slushfind \
    --name_prefix=rls-256-sw \
    --target_security_level=256 \
    --min_sig_count=30 \
    --max_sig_size=16000 \
    --min_sig_hashes=0 \
    --max_sig_hashes=100000000 \
    --max_verify_hashes=10000 \
    --fallback_security_level=192 \
    --eval_sig_size=1.0 \
    --eval_sig_hashes=0 \
    --eval_verify_hashes=0 \
    --table_format=markdown \
