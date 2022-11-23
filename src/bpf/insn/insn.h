#ifndef INSN_H
#define INSN_H

#define TASK_COMM_LEN 16
#define MAX_ENTRIES 512*1024*1024

struct insn_info {
  __u32 pid;
  unsigned char insn[15];
  char name[TASK_COMM_LEN];
};

#endif
