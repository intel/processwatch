#!/bin/bash
# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-2.0-only

###################################################################
#                           CLEAN.SH
# Cleans all dependency installations, build logs, and artifacts
# from the project itself. Throws no errors.
###################################################################

echo "Cleaning..."

rm -rf deps/install &> /dev/null || true
rm -rf deps/build_logs &> /dev/null || true

rm processwatch &> /dev/null || true
rm src/processwatch &> /dev/null || true
rm src/*.o &> /dev/null || true
rm src/ui/*.o &> /dev/null || true

rm src/bpf/insn/*.o &> /dev/null || true
rm src/bpf/insn/*.skel.h &> /dev/null || true
rm src/bpf/insn/vmlinux.h &> /dev/null || true

rm src/bpf/tma/*.o &> /dev/null || true
rm src/bpf/tma/*.skel.h &> /dev/null || true
rm src/bpf/tma/vmlinux.h &> /dev/null || true

echo "Finished cleaning."
