#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define FILE_PROCINFO 1
#include "config.h"
#include "helpers.h"
#include "procinfo.h"

char *get_proc_name(pid_t process) {
  char fname[UID_PATH_BUF + 1];
  char *pname = NULL;
  FILE *fp = NULL;
  int i = 0;
  size_t proc_cmdline_len = 0;

  snprintf(fname, sizeof(fname), "/proc/%d/cmdline", process);

  fp = fopen(fname, "rb");

  if (fp == NULL)
    goto end_get_proc_name;

  pname = (char *) calloc(sizeof(char) * UID_PATH_BUF+ 1, 1);
  if (!pname)
    goto end_get_proc_name;

  proc_cmdline_len = fread(pname, 1, UID_PATH_BUF, fp);
  for (i = 0; i < proc_cmdline_len; ++i) {
      if (pname[i] == '\0')
          pname[i] = ' ';
  }
  pname[UID_PATH_BUF] = '\0';

end_get_proc_name:
  if (fp)
    fclose(fp);

  return pname;
}

int get_proc_euid(pid_t process) {
  char fname[UID_PATH_BUF+ 1];
  char *status_contents = NULL;
  FILE *fp = NULL;
  int euid = -1;

  snprintf(fname, sizeof(fname), "/proc/%d/status", process);
  fp = fopen(fname, "rb");

  if (!fp)
    goto end_get_proc_euid;

  status_contents = (char *) calloc(sizeof(char) * UID_PATH_BUF + 1, 1);
  if (!status_contents)
    goto end_get_proc_euid;

  while (fgets(status_contents, UID_PATH_BUF, fp) != NULL) {
    sscanf(status_contents, "Uid:\t%d\n", &euid);

    if (euid != -1)
      break;
  }

end_get_proc_euid:
  if (fp)
    fclose(fp);

  free(status_contents);
  return euid;
}

char *get_proc_username(pid_t process) {
  struct passwd *pwd = NULL;
  int euid = get_proc_euid(process);
  char *username = (char *) calloc(sizeof(char) * UID_PATH_BUF + 1, 1);

  if (!username)
    return NULL;

  if (euid == -1) {
    strncpy(username, "unknown", 8);
    return username;
  }

  if ((pwd = getpwuid(euid)) != NULL)
    snprintf(username, UID_PATH_BUF, "%s", pwd->pw_name);

  return username;
}

char *get_proc_path(pid_t process) {
  char symlink_name[UID_PATH_BUF + 1];
  char *pname = NULL;
  int flen = 0;

  snprintf(symlink_name, sizeof(symlink_name), "/proc/%d/exe", process);
  pname = (char *) calloc(sizeof(char) * UID_PATH_BUF, 1);

  if (!pname)
    goto end_get_proc_path;

  flen = readlink(symlink_name, pname, sizeof(symlink_name) - 1);

  if (flen == -1) {
    free(pname);
    return NULL;
  }

  pname[flen] = '\0';

end_get_proc_path:
  return pname;
}
