#!/bin/bash
# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-2.0-only

# This script uses `awk` to construct maps.h.
# Instead of using preprocessor trickery, we
# simply loop over a counter (starting at 0)
# with `awk`, and define a map and accompanying
# function using that counter in their name.
# WARNING: ONLY `-O2` OPTIMIZATIONS ARE SUPPORTED

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
MAX_PERF_EVENTS=100

# Accepts one argument, and constructs a BPF code file
# with one map and one accessor function, named `map${1}.c`.
function make_map() {
  awk \
    -v i="${1}" \
  '
  BEGIN{
    printf("#include <vmlinux.h>\n");
    printf("#include <bpf/bpf_helpers.h>\n");
    printf("#include <bpf/bpf_tracing.h>\n");
    printf("#include <bpf/bpf_core_read.h>\n");
    printf("#include \"perf_slots.h\"\n");
    printf("#include \"map_utils.h\"\n");
    printf("DEFINE_MAP(%d);\n", i);
    printf("DEFINE_FUNCTION(%d);\n", i);
    printf("DEFINE_LICENSE\n");
  }
  ' > ${DIR}/maps/map${1}.bpf.c
}

function compile_bpf() {
  ${CLANG} ${BPF_CFLAGS} -target bpf -D__TARGET_ARCH_x86 \
    -I${DIR} -I${PREFIX}/include -c ${DIR}/maps/map${1}.bpf.c -o ${DIR}/maps/map${1}.bpf.o
}

function strip_bpf() {
  ${LLVM_STRIP} -g ${DIR}/maps/map${1}.bpf.o
}

rm -rf ${DIR}/maps
mkdir -p ${DIR}/maps
let MAX_PERF_EVENTS--

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

BATCH_SIZE=$(nproc)
for ITER in $(seq 0 ${MAX_PERF_EVENTS}); do
  ((i=i%BATCH_SIZE)); ((i++==0)) && wait
  make_map "${ITER}" &
done
wait

# Now, build the BPF object files
BATCH_SIZE=$(nproc)
for ITER in $(seq 0 ${MAX_PERF_EVENTS}); do
  ((i=i%BATCH_SIZE)); ((i++==0)) && wait
  compile_bpf "${ITER}" &
done
wait

BATCH_SIZE=$(nproc)
for ITER in $(seq 0 ${MAX_PERF_EVENTS}); do
  ((i=i%BATCH_SIZE)); ((i++==0)) && wait
  strip_bpf "${ITER}" &
done
wait

# Construct a list of BPF programs that we need to link together
FILES=""
for ITER in $(seq 0 ${MAX_PERF_EVENTS}); do
  FILES+="${DIR}/maps/map${ITER}.bpf.o "
done

# Try to link them.
${BPFTOOL} gen object ${DIR}/perf_slots.bpf.o ${FILES} # Only because I have multiple object files

${BPFTOOL} gen skeleton ${DIR}/perf_slots.bpf.o > ${DIR}/perf_slots.skel.h
