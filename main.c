
#include "data.h"
#include "instruction.h"
#include "process.h"
#include "registers.h"
#include "utils.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

void usage() { printf("usage: ./main <target> <arg1> <args2> ..."); }

int probe_file(char *filename) {
  int fd = open(filename, O_RDONLY);
  return fd;
}

struct Process {
  char name[256];
  pid_t pid;
};

int main(int argc, char **argv) {
  if (argc < 2) {
    usage();
    exit(EXIT_SUCCESS);
  }

  char *target = argv[1];
  if (probe_file(target) == -1) {
    panic("%s: file does not exist\n", target);
  }

  pid_t pid = fork();
  if (pid == -1) {
    panic("fork");
  } else if (pid == 0) {
    int s = ptrace(PTRACE_TRACEME);
    if (s == -1) {
      panic("child-process: ptrace_traceme failed\n");
    }

    execv(argv[1], argv + 1);
    panic("child-process: execv failed\n");

  } else {

    int status;
    if (waitpid(pid, &status, 0) == -1) {
      panic("could not stop child process\n");
    }

    printf("[+] child process %u stopped, happy hacking!\n", pid);

    struct user_regs_struct regs;
    memset(&regs, 0, sizeof regs);

    struct Instructions instructions;
    instructions_init(&instructions, 32000);

    struct InstructionTree tree;
    instruction_tree_init(&tree);

    while (1) {

      process_singlestep(pid);

      registers_read(&regs, pid);
      registers_print(&regs);

      struct Instruction *inst =
          instructions_read(pid, &instructions, regs.rip);
      struct InstructionData *data = instruction_data_create(inst, &regs);

      instruction_tree_insert(&tree, regs.rip, data);
      struct InstructionData *content = NULL;
      instruction_tree_find(&tree, regs.rip, &content);
      if (content) {
        printf("moo [%ld] = %s %s\n", content->inst->address,
               content->inst->mnemonic, content->inst->ops);
        fflush(stdout);
      }
      // instructions_print_current(&instructions);
      // instructions_print(&instructions);

      getchar();
    }

    instruction_tree_destroy(&tree);

    instructions_destroy(&instructions);
  }

  return 0;
}
