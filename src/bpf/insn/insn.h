/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef INSN_H
#define INSN_H

#define TASK_COMM_LEN 16
#define MAX_ENTRIES 512*1024*1024
#define MAX_STACK_ENTRIES 10240

#ifdef INSNPROF_STACKS
  #define PERF_MAX_STACK_DEPTH 127
#endif

struct insn_info {
  __u32 pid;
  unsigned char insn[15];
  char name[TASK_COMM_LEN];
#ifdef INSNPROF_STACKS  
  int user_stack_id;
#endif
};

#endif
