#!/bin/bash
# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-2.0-only

###################################################################
#                           BUILD.SH
# This is the main build script for Process Watch. It first uses
# `build_deps.sh` to build the dependencies in the `deps` directory,
# then builds the BPF and userspace programs.
###################################################################
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# USER-CHANGEABLE OPTIONS
export CLANG="clang"
export CLANGXX="clang++"
export LLVMSTRIP="llvm-strip"
export PW_CC="${CLANG}"
export PW_CXX="${CLANGXX}"
export BPFTOOL="bpftool"
export CMAKE="cmake"

if ! command -v ${CMAKE} &> /dev/null; then
  export CMAKE="cmake3"
  if ! command -v ${CMAKE} &> /dev/null; then
    echo "Could not find CMake. I tried 'cmake' and 'cmake3'."
    exit 1
  fi
fi

# Command-line arguments
export DEBUG=false
export LEGACY=false
export TMA=false
export BUILD_DEPS=true
usage() { echo "Usage: $0 [-l] [-t] [-b] [-d]" 1>&2; exit 1; }
while getopts ":ltbd" arg; do
  case $arg in
    l)
      LEGACY=true
      ;;
    t)
      # This is an experimental feature that could be enabled in a future version
      TMA=true
      ;;
    b)
      BUILD_DEPS=false
      ;;
    d)
      DEBUG=true
      ;;
  esac
done

# These are used to compile the dependencies
DEPS_DIR="${DIR}/deps"

# We export these because they're used by src/build.sh
export PREFIX="${DEPS_DIR}/install"

export PW_LDFLAGS="-Wl,-z,now"
export PW_CFLAGS="-O2 -Wall -D_FORTIFY_SOURCE=2"
export CFLAGS="-O2 -Wall"
export BPF_CFLAGS="-O2 -Wall -g"

if [ "${DEBUG}" = true ]; then
  export PW_CFLAGS="${PW_CFLAGS} -g -fsanitize=address -static-libsan"
  export PW_LDFLAGS="${PW_LDFLAGS} -g -fsanitize=address -static-libsan"
  export CFLAGS="${CFLAGS} -g"
fi

if [ "${LEGACY}" = true ]; then
  export BPF_CFLAGS="${BPF_CFLAGS} -DINSNPROF_LEGACY_PERF_BUFFER"
  export PW_CFLAGS="${PW_CFLAGS} -DINSNPROF_LEGACY_PERF_BUFFER"
fi
if [ "${TMA}" = true ]; then
  export PW_CFLAGS="${PW_CFLAGS} -DTMA"
fi

# Prepare the dependency-building logs
if [ "${BUILD_DEPS}" = true ]; then
  BUILD_LOGS=${DEPS_DIR}/build_logs
  rm -rf ${BUILD_LOGS} || true
  mkdir -p ${BUILD_LOGS} || true
fi

cd ${DIR}
git submodule init
git submodule update

###################################################################
#                            deps
###################################################################
if [ "${BUILD_DEPS}" = true ]; then
  echo "Compiling dependencies..."
  source ${DIR}/deps/build_deps.sh
fi

export PATH="${PREFIX}/bin:${PATH}"

# libbpf
export PW_LDFLAGS="${PW_LDFLAGS} ${PREFIX}/lib/libbpf.a"

# Zydis
if [ "${TMA}" = false ]; then
  if [ -f "${PREFIX}/lib/libZydis.a" ]; then
    export ZYDIS_STATIC_LIB="${PREFIX}/lib/libZydis.a"
  else
    export ZYDIS_STATIC_LIB="${PREFIX}/lib64/libZydis.a"
  fi
  export PW_LDFLAGS="${PW_LDFLAGS} ${ZYDIS_STATIC_LIB}"
fi

# tinyexpr
if [ "${TMA}" = true ]; then
  export PW_LDFLAGS="${PW_LDFLAGS} ${DIR}/src/tinyexpr.o -lm"
fi

# jevents
if [ "${TMA}" = true ]; then
  export PW_LDFLAGS="${PW_LDFLAGS} ${PREFIX}/lib/libjevents.a"
fi
        
###################################################################
#                     Process Watch itself
###################################################################
export CC="${PW_CC}"
export CXX="${PW_CXX}"
${DIR}/src/build.sh
cp ${DIR}/src/processwatch ${DIR}
