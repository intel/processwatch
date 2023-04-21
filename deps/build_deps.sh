#!/bin/bash
# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-2.0-only

###################################################################
#                              NOTE
#  This is NOT meant to be used standalone. It relies on an
#  environment variable,"TMA", which is set by build.sh.
###################################################################
BUILD_DEPS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# These are used to compile the dependencies
DEPS_DIR="${BUILD_DEPS_DIR}"
BPFTOOL_SRC_DIR="${DEPS_DIR}/bpftool/src"
ZYDIS_SRC_DIR="${DEPS_DIR}/zydis"
TINYEXPR_SRC_DIR="${DEPS_DIR}/tinyexpr"
JEVENTS_SRC_DIR="${DEPS_DIR}/pmu-tools/jevents"

# We export these because they're used by src/build.sh
export PREFIX="${DEPS_DIR}/install"
export CFLAGS="-O2 -Wall"

# Prepare the dependency-building logs
BUILD_LOGS=${DEPS_DIR}/build_logs
rm -rf ${BUILD_LOGS} || true
mkdir -p ${BUILD_LOGS} || true

git submodule init
git submodule update

###################################################################
#                            bpftool
###################################################################
# Compile a standalone copy of bpftool. This is so that we no longer
# have to depend on the user installing `linux-tools` packages or
# equivalent, since that can sometimes be a pain, especially if
# they're not running the latest available kernel for their
# distribution. Also builds a static copy of libbpf.
if ! command -v ${BPFTOOL} &> /dev/null; then
  echo "  No system bpftool found! Compiling libbpf and bpftool..."

  cd ${BPFTOOL_SRC_DIR}

  make &>> ${BUILD_LOGS}/bpftool.log
  RETVAL=$?
  if [ ${RETVAL} -ne 0 ]; then
    echo "  Building bpftool failed. Please see ${BUILD_LOGS}/bpftool.log for more details."
    exit 1
  fi

  # Install the bpftool binary and the static libbpf.a
  mkdir -p ${PREFIX}/bin
  mkdir -p ${PREFIX}/lib
  mkdir -p ${PREFIX}/include
  cp bpftool ${PREFIX}/bin/bpftool
  cp libbpf/libbpf.a ${PREFIX}/lib/libbpf.a
  cp -r libbpf/include/* ${PREFIX}/include/

  export PATH="${PREFIX}/bin:${PATH}"
else
  echo "  Using system bpftool."
fi


###################################################################
#                              zydis
###################################################################

if [ "${TMA}" = false ]; then
  echo "  Compiling zydis..."
  
  mkdir -p "${PREFIX}"
  cd ${ZYDIS_SRC_DIR}
  
  # Zycore, the only dependency of Zydis
  cd dependencies/zycore
  rm -rf build \
    &>> ${BUILD_LOGS}/zydis.log
  mkdir build \
    &>> ${BUILD_LOGS}/zydis.log
  cd build
    &>> ${BUILD_LOGS}/zydis.log
  ${CMAKE} \
    -DCMAKE_INSTALL_PREFIX=${PREFIX} \
    .. \
    &>> ${BUILD_LOGS}/zydis.log
  RETVAL=$?
  if [ ${RETVAL} -ne 0 ]; then
    echo "  Compiling Zycore failed. Please check ${BUILD_LOGS}/zydis.log for more details."
    exit 1
  fi
  
  make \
    &>> ${BUILD_LOGS}/zydis.log
  RETVAL=$?
  if [ ${RETVAL} -ne 0 ]; then
    echo "  Compiling Zydis failed. Please check ${BUILD_LOGS}/zydis.log for more details."
    exit 1
  fi
  make install \
    &>> ${BUILD_LOGS}/zydis.log
  
  # Zydis itself
  cd ${ZYDIS_SRC_DIR}
  rm -rf build && mkdir build && cd build
  ${CMAKE} \
    -DCMAKE_INSTALL_PREFIX=${PREFIX} \
    -DZYDIS_FEATURE_ENCODER=OFF \
    -DZYDIS_BUILD_EXAMPLES=OFF \
    -DZYDIS_BUILD_TOOLS=OFF \
    -DZYDIS_FEATURE_AVX512=ON \
    .. \
    &>> ${BUILD_LOGS}/zydis.log
  RETVAL=$?
  if [ ${RETVAL} -ne 0 ]; then
    echo "Compiling Zydis failed. Please check ${BUILD_LOGS}/zydis.log for more details."
    exit 1
  fi
    
  make \
    &>> ${BUILD_LOGS}/zydis.log
  RETVAL=$?
  if [ ${RETVAL} -ne 0 ]; then
    echo "Compiling Zydis failed. Please check ${BUILD_LOGS}/zydis.log for more details."
    exit 1
  fi
  make install \
    &>> ${BUILD_LOGS}/zydis.log
  
  cd ${DEPS_DIR}
fi

###################################################################
#                            tinyexpr
###################################################################
# tinyexpr is used by the TMA portion to convert event values
# (for example, the number of cycles or instructions) into metrics
# via an expression (for example, CPI would be "cycles / instructions."
if [ "${TMA}" = true ]; then
  echo "  Compiling tinyexpr..."
  
  cd ${TINYEXPR_SRC_DIR}
  clang -c tinyexpr.c -o tinyexpr.o
  cp tinyexpr.o ${DEPS_DIR}/src
  mkdir -p ${PREFIX}/include
  cp tinyexpr.h ${PREFIX}/include
  cd ${DEPS_DIR}
fi

###################################################################
#                            jevents
###################################################################
# Next, compile jevents-- we use this to convert event names to their
# corresponding perf_event_attr.
if [ "${TMA}" = true ]; then
  echo "  Compiling jevents..."
  
  make -C ${JEVENTS_SRC_DIR} clean \
    &>> ${BUILD_LOGS}/jevents.log
  RETVAL=$?
  if [ ${RETVAL} -ne 0 ]; then
    echo "Cleaning jevents failed. Please check ${BUILD_LOGS}/jevents.log for more details."
    exit 1
  fi
  make -C ${JEVENTS_SRC_DIR} \
    &>> ${BUILD_LOGS}/jevents.log
  RETVAL=$?
  if [ ${RETVAL} -ne 0 ]; then
    echo "Compiling jevents failed. Please check ${BUILD_LOGS}/jevents.log for more details."
    exit 1
  fi
  cp ${JEVENTS_SRC_DIR}/libjevents.a ${PREFIX}/lib \
    &>> ${BUILD_LOGS}/jevents.log
  cp ${JEVENTS_SRC_DIR}/*.h ${PREFIX}/include \
    &>> ${BUILD_LOGS}/jevents.log
fi
