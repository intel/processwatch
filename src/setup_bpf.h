/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#pragma once

#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <sys/mman.h>

#include "bpf/insn/insn.h"
#include "bpf/insn/insn.skel.h"

/*******************************************************************************
*                            PERF_EVENT_OPEN WRAPPER
*******************************************************************************/

/**
  Loose wrapper around perf_event_open. Opens a perf_event_attr
  on each CPU, for all processes, and then attaches that event
  to the given BPF program and link.
**/
static int open_and_attach_perf_event(struct perf_event_attr *attr, int cpu, int pid, int group_fd) {
  int fd;

  fd = syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, 0);
  if(fd < 0) {
    /* Ignore CPU that is offline */
    if(errno == ENODEV) {
      return -2;
    }
    fprintf(stderr, "Failed to initialize perf sampling: %s\n",
      strerror(errno));
    return -1;
  }
  
  /* Add a link to the array. Note that bpf_info->prog gets incremented
     per perf event. */
  bpf_info->num_links++;
  bpf_info->links = realloc(bpf_info->links, sizeof(struct bpf_link *) * bpf_info->num_links);
  if(!bpf_info->links) {
    fprintf(stderr, "Failed to allocate memory! Aborting.\n");
    exit(1);
  }
  bpf_info->links[bpf_info->num_links - 1] = bpf_program__attach_perf_event(*(bpf_info->prog), fd);
  if(libbpf_get_error(bpf_info->links[bpf_info->num_links - 1])) {
    fprintf(stderr, "failed to attach perf event on cpu: "
      "%d\n", cpu);
    /* Set this pointer to NULL, since it's undefined what it will be */
    bpf_info->links[bpf_info->num_links - 1] = NULL;
    close(fd);
    return -1;
  }
  
  return fd;
}

/**
  single_insn_event - Handles a single CPU, PMU, socket event.
  Returns:
    >0 if successful.
    -1 if there was an issue with perf.
    -2 if the CPU was offline.
**/
static int single_insn_event(int cpu, int pid) {
  int retval;
  
  /* Architecture-independent settings */
  struct perf_event_attr attr = {
    .sample_period = pw_opts.sample_period,
    .sample_type = PERF_SAMPLE_IDENTIFIER,
    .read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING,
    .exclude_guest = 1,
    .inherit = 1,
    .size = sizeof(struct perf_event_attr),
  };
  
#ifdef __aarch64__
  attr.type = PERF_TYPE_RAW;
  attr.config = 0x08;
#elif __x86_64__
  get_pmu_string(bpf_info->pmu_name);
  /* Program INST_RETIRED.ANY (or equivalent) depending on PMU version */
  if(strncmp(bpf_info->pmu_name, "skylake", 7) == 0) {
    attr.type = PERF_TYPE_RAW;
    attr.config = 0x00c0;
  } else if(strncmp(bpf_info->pmu_name, "icelake", 7) == 0) {
    attr.type = PERF_TYPE_RAW;
    attr.config = 0x00c0;
  } else if(strncmp(bpf_info->pmu_name, "sapphire_rapids", 7) == 0) {
    attr.type = PERF_TYPE_RAW;
    attr.config = 0x00c0;
  } else if(strncmp(bpf_info->pmu_name, "ibs_op", 6) == 0) {
    attr.type = get_ibs_op_type();
    if (attr.type < 0)
	    return -1;
    attr.config = 0x80000;
    attr.exclude_guest = 0;
  } else {
    attr.type = PERF_TYPE_SOFTWARE;
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
  }
#endif

  /* Attach the event, and handle the BPF linkages. */
  retval = open_and_attach_perf_event(&attr, cpu, pid, -1);
  if(retval == -1) {
    fprintf(stderr, "Failed to open perf event.\n");
    return -1;
  } else if(retval == -2) {
    fprintf(stderr, "WARNING: CPU %d is offline.\n", cpu);
    return -2;
  }

  return retval;
}

static int init_insn_bpf_info() {
  int err;
  struct bpf_object_open_opts opts = {0};
  
  opts.sz = sizeof(struct bpf_object_open_opts);
  if(pw_opts.btf_custom_path) {
    opts.btf_custom_path = pw_opts.btf_custom_path;
  }
  
  bpf_info->obj = insn_bpf__open_opts(&opts);
  if(!bpf_info->obj) {
    fprintf(stderr, "ERROR: Failed to get BPF object.\n");
    fprintf(stderr, "       Most likely, one of two things are true:\n");
    fprintf(stderr, "       1. You're not root.\n");
    fprintf(stderr, "       2. You don't have a kernel that supports BTF type information.\n");
    return -1;
  }
  err = insn_bpf__load(bpf_info->obj);
  if(err) {
    fprintf(stderr, "Failed to load BPF object!\n");
    return -1;
  }

  bpf_info->prog = (struct bpf_program **) &(bpf_info->obj->progs.insn_collect);
  bpf_info->links = NULL;
  bpf_info->num_links = 0;
  
  /* Construct the ringbuffer or perfbuffer */
#ifdef INSNPROF_LEGACY_PERF_BUFFER
  struct perf_buffer_opts pb_opts = {};
  pb_opts.sz = sizeof(struct perf_buffer_opts);
  bpf_info->pb = perf_buffer__new(bpf_map__fd(bpf_info->obj->maps.pb),
                                  MAX_ENTRIES / (4096 * 1024),
                                  handle_sample,
                                  NULL,
                                  NULL,
                                  &pb_opts);
  if(!(bpf_info->pb)) {
    fprintf(stderr, "Failed to create a new perf buffer. You're most likely not root.\n");
    return -1;
  }
#else
  bpf_info->rb = ring_buffer__new(bpf_map__fd(bpf_info->obj->maps.rb), handle_sample, NULL, NULL);
  if(!(bpf_info->rb)) {
    fprintf(stderr, "Failed to create a new ring buffer. You're most likely not root.\n");
    return -1;
  }
#endif
  
  bpf_info->nr_cpus = libbpf_num_possible_cpus();
  return 0;
}
  

/**
  deinit_bpf_info: Deinitializes and frees everything in the structure.
*/
static void deinit_bpf_info() {
  int i;
  
  if(!bpf_info) {
    return;
  }
  
  if(bpf_info->obj) {
    insn_bpf__destroy(bpf_info->obj);
  }
#ifdef INSNPROF_LEGACY_PERF_BUFFER
  if(bpf_info->pb) {
    perf_buffer__free(bpf_info->pb);
  }
#else
  if(bpf_info->rb) {
    ring_buffer__free(bpf_info->rb);
  }
#endif
  
  if(bpf_info->links) {
    for(i = 0; i < bpf_info->num_links; i++) {
      bpf_link__destroy(bpf_info->links[i]);
    }
    free(bpf_info->links);
  }
  free(bpf_info);
}

static int program_events(int pid) {
  int retval, cpu;
  
  if(init_insn_bpf_info() == -1) {
    return -1;
  }
  
  retval = 0;
  if(pid == -1) {
    for(cpu = 0; cpu < bpf_info->nr_cpus; cpu++) {
      retval = single_insn_event(cpu, pid);
      if(retval == -2) { // cpu is offline
        continue;
      }
      if(retval < 0) {
        return -1;
      }
    }
  } else {
    retval = single_insn_event(-1, pid);
    if(retval < 0) {
      return -1;
    }
  }
  
  return retval;
}
