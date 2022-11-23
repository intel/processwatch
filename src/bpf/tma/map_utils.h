#pragma once

#define MAX_ENTRIES  8192

#define STRUCT_NAME(FIRST, SECOND) \
  FIRST##SECOND
#define SECTION_NAME(FIRST, SECOND) \
  SEC(FIRST # SECOND)
#define FUNC_NAME(FIRST, SECOND) \
  FIRST##SECOND

/**
  The `DEFINE_MAP` macro simply defines a BPF map titled
  `perf_slot_map_[num]`, which stores information about
  a single perf event counter.
**/
#define DEFINE_MAP(_VAL_) \
  struct { \
    __uint(type, BPF_MAP_TYPE_HASH); \
    __uint(max_entries, MAX_ENTRIES); \
    __type(key, __u64); \
    __type(value, __u64); \
  } STRUCT_NAME(perf_slot_map_, _VAL_) SEC(".maps");

/**
  Next, define a macro which takes an index as an argument, and which
  stores the `perf` counters' values in the BPF map associated with that index.
**/
#define INC_TASK_INFO(sample_period, index) \
  __u64 pid, key, val, *val_ptr; \
  __u32 cpu; \
  int err; \
  unsigned int task_flags; \
  struct task_struct *task; \
  \
  cpu = bpf_get_smp_processor_id(); \
  pid = bpf_get_current_pid_tgid(); \
  key = (pid & 0xFFFFFFFF00000000) | cpu ; \
  val = 0; \
  \
  val_ptr = bpf_map_lookup_elem(&( perf_slot_map_##index ), &key); \
  if(!val_ptr) { \
    val_ptr = &val; \
    task = (struct task_struct *) bpf_get_current_task(); \
    err = bpf_core_read(&task_flags, sizeof(unsigned int), &task->flags); \
    if(!err) { \
      if(task_flags & 0x00200000) { \
        return 0; \
      } \
    } else { \
      return 0; \
    } \
  } \
  \
  __sync_fetch_and_add(val_ptr, sample_period); \
  \
  if(val_ptr == &val) { \
    bpf_map_update_elem(&perf_slot_map_ ## index, &key, val_ptr, 0); \
  } \
  \
  return 0;

/**
  This defines a macro which defines a `perf_event_[num]` function for us.
  Each of these functions is associated with one of the above BPF maps.
  When invoked, they store their counters in `perf_slot_map_[num]`.
  They use the above INC_TASK_INFO macro to accomplish this.
**/
#define DEFINE_FUNCTION(index) \
SECTION_NAME("perf_event/", index) \
int FUNC_NAME(perf_event_, index) (struct bpf_perf_event_data *ctx) { \
  INC_TASK_INFO(ctx->sample_period, index); \
}

#define DEFINE_LICENSE \
  char __license[] __attribute__((section("license"), used)) = "GPL";
