#ifndef _PROCESS_H_
#define _PROCESS_H_

#include "utils.h"
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int singlestep_worked(int status) {
  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
    return 1;
  else
    return -1;
}

void process_singlestep(pid_t pid) {
  int s = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
  if (s == -1) {
    panic("parent-process: could not singlestep process %u\n", pid);
  }
  int status;
  s = waitpid(pid, &status, 0);
  if (s == -1) {
    panic("could not receive child signal\n");
  }

  if (singlestep_worked(status)) {
    printf("[+] successfuly stopped [sig = %d] child processes after "
           "singlestep\n",
           WSTOPSIG(status));
  } else {
    panic("could not stop child process after singlestep, help!\n");
  }
}

#endif // __PROCESS_H_
