/* Copyright (C) 2022 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef INSNPROF_KERNINFO
#define INSNPROF_KERNINFO

#include <stdio.h>

#ifdef __x86_64__

/* Return value: >0: Valid, -1: Error */
static int get_ibs_op_type(void) {
  static int type = -1; /* -1 : Unknown, 0: Failed to read first time, >0: Valid */
  FILE *fp;
  int ret;

  if (type != -1) {
    if (!type)
      return -1;
    return type;
  }

  fp = fopen("/sys/bus/event_source/devices/ibs_op/type", "r");
  if (!fp) {
    fprintf(stderr, "Failed to find ibs_op// pmu sysfs. [%m]\n");
    type = 0;
    return -1;
  }

  ret = fscanf(fp, "%d", &type);
  fclose(fp);
  if (ret != 1) {
    fprintf(stderr, "Failed to read ibs_op// type. [%m]\n");
    type = 0;
    return -1;
  }
  return type;
}

void get_vendor(char *vendor) {
  unsigned int a[4];

  asm (
    /* %rbx must be preserved. */
    "mov %%rbx, %%rdi\n"
    "cpuid\n"
    "xchg %%rdi, %%rbx\n"
    : "=a"(a[0]), "=D"(a[1]), "=c"(a[2]), "=d"(a[3])
    : "a"(0)
  );
  strncpy(&vendor[0], (char *)&a[1], 4);
  strncpy(&vendor[4], (char *)&a[3], 4);
  strncpy(&vendor[8], (char *)&a[2], 4);
}

int is_amd_arch(void) {
  static int amd = -1; /* -1: Unknown, 1: Yes, 0: No */
  char vendor[13] = {0};

  if (amd != -1)
    return amd;

  get_vendor(vendor);
  amd = strcmp(vendor, "AuthenticAMD") ? 0 : 1;
  return amd;
}

void get_pmu_string(char *pmu_name) {
  FILE *f;
  size_t retval;

  if (is_amd_arch()) {
    f = fopen("/sys/bus/event_source/devices/ibs_op", "r");
    if (!f) {
      fprintf(stderr, "WARNING: Unable to open '/sys/bus/event_source/devices/ibs_op'. "
                      "Using software events.\n");
      strcpy(pmu_name, "invalid");
      return;
    }
    fclose(f);
    strcpy(pmu_name, "ibs_op");
    return;
  }

  f = fopen("/sys/devices/cpu/caps/pmu_name", "r");
  if(!f) {
    fprintf(stderr, "WARNING: Unable to open '/sys/devices/cpu/caps/pmu_name'. Using software events.\n");
    strcpy(pmu_name, "invalid");
    return;
  }
  retval = fread(pmu_name, sizeof(char), 31, f);
  if(retval == 0) {
    fprintf(stderr, "WARNING: Unable to read '/sys/devices/cpu/caps/pmu_name'. Using software events.\n");
    strcpy(pmu_name, "invalid");
    return;
  }
  fclose(f);
  
}

#endif

#define MINIMUM_ISA_SUPPORT \
    fprintf(stderr, "Failed to parse '/proc/cpuinfo'! Assuming minimum ISA support.\n"); \
    return 0;

/* It's either this, or I call `lscpu` and parse its output. */
char supports_amx_tile() {
  FILE *cpu_info = fopen("/proc/cpuinfo", "r");
  char *buff, *buff2, *buff_orig, found;
  int chars_read;
  size_t n;
  ssize_t nread;
  
  if(cpu_info == NULL) {
    MINIMUM_ISA_SUPPORT;
  }

  buff = NULL;
  found = 0;
  while(!found && !feof(cpu_info)) {
    if(fscanf(cpu_info, "%*[^f]") == EOF) {
      MINIMUM_ISA_SUPPORT;
    }
    found = fscanf(cpu_info, "flags%m[^:]", &buff) == 1;
  }
  fseek(cpu_info, 1, SEEK_CUR);
  free(buff);

  buff = NULL;
  nread = getline(&buff, &n, cpu_info);
  fclose(cpu_info);
  if(nread <= 0) {
    MINIMUM_ISA_SUPPORT;
  }
  buff_orig = buff;

  found = 0;
  while(!found) {
    nread = sscanf(buff, "%ms%n", &buff2, &chars_read);
    if((nread == EOF) || (nread == 0)) {
      break;
    }
    buff += chars_read;
    if(!strcmp(buff2, "amx_tile")) {
      found = 1;
    }
    free(buff2);
  }
  free(buff_orig);
  
  if(found) {
    return 1;
  }
  return 0;
}

#endif
