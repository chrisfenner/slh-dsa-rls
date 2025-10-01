#!/bin/sh

# Script to print detailed info for selected parameter sets

set -e

go run ./cmd/analyze <<EOF
rls128cs1 112 16 1 22 24 6 2
rls192cs1 128 24 1 21 25 9 3
rls256cs1 192 32 1 21 25 12 2
SLH-DSA-128s 112 16 7 9 12 14 4
SLH-DSA-128f 112 16 22 3 6 33 4
SLH-DSA-192s 128 24 7 9 14 17 4
SLH-DSA-192f 128 24 22 3 8 33 4
SLH-DSA-256s 192 32 8 8 14 22 4
SLH-DSA-256f 192 32 17 4 9 35 4
EOF
