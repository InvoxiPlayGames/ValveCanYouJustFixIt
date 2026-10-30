#!/usr/bin/env bash
sudo tc qdisc del dev lo clsact
sudo tc qdisc add dev lo clsact
sudo tc filter add dev lo egress bpf da obj ebpf_source_password.o sec tc
