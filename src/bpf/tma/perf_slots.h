/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef PERFSCOPE_H
#define PERFSCOPE_H

/**
  This is the maximum number of perf events that the eBPF program
  can currently handle. Of course, change this value you modify
  the associated eBPF code.
**/
#define MAX_PERF_EVENTS 100
#define MAX_GROUPS 50

#endif
