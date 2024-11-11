#ifndef REGISTERS_H_
#define REGISTERS_H_

#include "utils.h"
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

void registers_print(struct user_regs_struct *regs) {
  if (!regs) {
    printf("[-] could not print registers, regs NULL\n");
  }
  printf("RIP: %lld\r\n", regs->rip);
  /* printf("RAX: %lld\r\n", regs->rax); */
  /* printf("RBX: %lld\r\n", regs->rbx); */
  /* printf("RCX: %lld\r\n", regs->rcx); */
  /* printf("RDX: %lld\r\n", regs->rdx); */
  /* printf("RSI: %lld\r\n", regs->rsi); */
  /* printf("RDI: %lld\r\n", regs->rdi); */
  /* printf("RBP: %lld\r\n", regs->rbp); */
  /* printf("RSP: %lld\r\n", regs->rsp); */
  /* printf("R8: %lld\r\n", regs->r8); */
  /* printf("R9: %lld\r\n", regs->r9); */
  /* printf("R10: %lld\r\n", regs->r10); */
  /* printf("R11: %lld\r\n", regs->r11); */
  /* printf("R12: %lld\r\n", regs->r12); */
  /* printf("R13: %lld\r\n", regs->r13); */
  /* printf("R14: %lld\r\n", regs->r14); */
  /* printf("R15: %lld\r\n", regs->r15); */
  /* printf("EFLAGS: %lld\r\n", regs->eflags); */
}

void registers_read(struct user_regs_struct *regs, pid_t pid) {
  int s = ptrace(PTRACE_GETREGS, pid, NULL, regs);
  if (s == -1) {
    printf("[-] could not read registers\n");
  }
}
#endif // REGISTERS_H_
