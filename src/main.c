#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <assert.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <getopt.h>

#define FILE_MAIN 1
#include "config.h"
#include "helpers.h"
#include "plisten.h"

char *outfile = "/dev/null";

void exitsig(int x) {
  fatal("parent: Exiting on signal %d.\n", x);
}

void handlechild(int x) {
  int status = 0;

  pid_t childpid = wait(&status);

  int exit_status = WEXITSTATUS(status);
  int normal_exit = WIFEXITED(status);

  //Did the child not exit() or return from main?
  if (!normal_exit) {
    int signal_term = WTERMSIG(status);
    fatal("parent: Child process %d died with %s (%d).\n",
        childpid, strsignal(signal_term), status);
  }

  //Propagate the child exit code
  exit(exit_status);
}

void needroot(void) {
  fatal("You don't have permission attach to other users processes\n"
        " [hint] you need to sudo or be root or something\n"
        " [hint] i hear someone has lpes\n"
  );
}

void usage(char *self) {
  debug("Usage: %s [ -d ] [ -o file.txt ]\n"
        " -d - daemonize (reccommend using with -o flag)\n"
        " -o - output file\n"
        " output is dumped to stdout unless an output file is specified\n"
        " stdout will be /dev/null if you daemonize\n",
        self);
  exit(3);
}

void daemonize(int argc, char *argv[], char *envp[]) {
  pid_t child = 0;
  int i = 0;
  int nfd = 0;
  int ofd = 0;
  int efd = 0;
  int chdir_flag = 0;

  child = fork();

  if (child < 0) exit(1);
  if (child > 0) exit(0);

  setsid();
  child = fork();

  if (child < 0) exit(1);
  if (child > 0) exit(0);

  umask(0);
  chdir_flag = chdir(ROOT_DIR);
  assert(chdir_flag == 0);

  for (i = 0; i < getdtablesize(); i++)
    close(i);

  nfd = open("/dev/null", O_RDWR);
  assert(nfd == 0);

  ofd = open(outfile, O_RDWR | O_CREAT | O_APPEND, 0600);
  assert(ofd == 1);

  efd = dup(ofd);
  assert(efd == 2);

  plisten();
}

void terminal(int argc, char *argv[], char *envp[]) {
  pid_t child = 0;

  child = fork();
  if (child == 0) {
    plisten();
  } else {
    while (1) { sleep(1); }
  }
}

int main(int argc, char *argv[], char *envp[]) {
  int opt = 0;
  int daemon = 0;

  signal(SIGINT, exitsig);
  signal(SIGQUIT, exitsig);
  signal(SIGHUP, exitsig);
  signal(SIGPIPE, exitsig);
  signal(SIGTERM, exitsig);
  signal(SIGSEGV, exitsig);
  signal(SIGBUS, exitsig);
  signal(SIGILL, exitsig);
  signal(SIGCHLD, handlechild);

  if (geteuid() != 0) needroot();

  while ((opt = getopt(argc, (void*)argv, "do:")) != EOF) {
    switch(opt) {
      case 'd': daemon = 1; break;
      case 'o':
        outfile = calloc(strlen(optarg) + 1, 1);
        sscanf(optarg, "%s", outfile);
        break;
      default: usage(argv[0]);
    }
  }

  if (daemon) daemonize(argc, argv, envp);
  else terminal(argc, argv, envp);

  return 0;
}
