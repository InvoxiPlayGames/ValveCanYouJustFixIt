#!/usr/bin/env bash
clang -O2 -target bpf -c ebpf_source_password.c -o ebpf_source_password.o
