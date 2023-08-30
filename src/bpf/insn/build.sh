#!/bin/bash
# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-2.0-only

# WARNING: ONLY `-O2` OPTIMIZATIONS ARE SUPPORTED
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Building the 'insn' BPF program:"

# Get this kernel's `vmlinux.h`
echo "  Gathering BTF information for this kernel..."
${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > ${DIR}/vmlinux.h
RETVAL="$?"
if [ $RETVAL -ne 0 ]; then
  echo "    Your current kernel does not have BTF information."
  echo "    This is required for running eBPF programs."
  echo "    For the purposes of compiling eBPF, though, we'll just use"
  echo "    a pre-generated vmlinux.h."
  cp ${DIR}/../vmlinux_505.h ${DIR}/vmlinux.h
fi

# Compile the BPF object code
echo "  Compiling the BPF program..."
${CLANG} ${BPF_CFLAGS} -target bpf -D__TARGET_ARCH_x86 \
  -I${DIR} -I${PREFIX}/include -c ${DIR}/insn.bpf.c -o ${DIR}/insn.bpf.o

# Strip the object file (for a smaller filesize)
echo "  Stripping the object file..."
${LLVM_STRIP} -g ${DIR}/insn.bpf.o

# Compile the object file into the skeleton header
echo "  Generating the BPF skeleton header..."
${BPFTOOL} gen skeleton ${DIR}/insn.bpf.o > ${DIR}/insn.skel.h
