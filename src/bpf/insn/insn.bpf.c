/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "insn.h"

#ifdef INSNPROF_LEGACY_PERF_BUFFER

/**
  PERFBUFFER INTERFACE: AVAILABLE EARLIER THAN 5.8.0.
**/

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
} pb SEC(".maps");

SEC("perf_event")
int insn_collect(struct bpf_perf_event_data *ctx) {
  u32 cpu;
  struct insn_info insn_info = {};
  long retval;
  
  /* Construct the insn_info struct */
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  insn_info.pid = pid;

  retval = bpf_probe_read_user(insn_info.insn, 15, (void *) ctx->regs.ip);
  if(retval < 0) {
    return 0;
  }
  bpf_get_current_comm(insn_info.name, sizeof(insn_info.name));
  
  /* Place insn_info in the ringbuf */
#ifdef BPF_F_CURRENT_CPU
  bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &insn_info, sizeof(struct insn_info));
#else
  cpu = bpf_get_smp_processor_id();
  bpf_perf_event_output(ctx, &pb, cpu, &insn_info, sizeof(struct insn_info));
#endif
  
  return 0;
}

#else

/**
  RINGBUFFER INTERFACE: REQUIRES LINUX 5.8.0.
**/

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, MAX_ENTRIES);
} rb SEC(".maps");

SEC("perf_event")
int insn_collect(struct bpf_perf_event_data *ctx) {
  struct insn_info *insn_info;
  long retval = 0;
  
  /* Reserve space for this entry */
  insn_info = bpf_ringbuf_reserve(&rb, sizeof(struct insn_info), 0);
  if(!insn_info) {
    return 1;
  }
  
  /* Construct the insn_info struct */
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  insn_info->pid = pid;

#ifdef __TARGET_ARCH_arm
  retval = bpf_probe_read_user(insn_info->insn, 4, (void *) ctx->regs.pc);
#elif __TARGET_ARCH_x86
  retval = bpf_probe_read_user(insn_info->insn, 15, (void *) ctx->regs.ip);
#endif
  if(retval < 0) {
    bpf_ringbuf_discard(insn_info, BPF_RB_NO_WAKEUP);
    return 1;
  }
  bpf_get_current_comm(insn_info->name, sizeof(insn_info->name));
  
  /* Place insn_info in the ringbuf */
  bpf_ringbuf_submit(insn_info, BPF_RB_NO_WAKEUP);
  
  return 0;
}

#endif

char LICENSE[] SEC("license") = "GPL";
