
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
#include "instruction_stack.h"

void usage(void) { printf("usage: ./main <target> <arg1> <args2> ..."); }

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

    struct InstructionTree tree;
    instruction_tree_init(&tree);

    struct InstructionStack instruction_stack;
    instruction_stack_init(&instruction_stack);

    while (1) {

      process_singlestep(pid);

      registers_read(&regs, pid);
      registers_print(&regs);

      size_t bytes_read;
      struct Instruction *inst =
          instruction_read(pid, regs.rip, &bytes_read);
      printf("[read %ld] ", bytes_read);
      struct InstructionData *data = instruction_data_create(inst, &regs);

      instruction_tree_insert(&tree, regs.rip, data);


      //instruction_stack_push(&instruction_stack, data);
      //instruction_stack_print(&instruction_stack);

      /*struct InstructionData *content = NULL;*/
      /*instruction_tree_find(&tree, regs.rip, &content);*/
      /*if (content) {*/
      /*  printf("[%ld] = %s %s\n", content->inst->address,*/
      /*         content->inst->mnemonic, content->inst->ops);*/
      /*  fflush(stdout);*/
      /*}*/
      struct Instruction *instruction = NULL;
      instruction_tree_find_as_instruction(&tree, regs.rip, &instruction);
      instruction_print(instruction);

      //instruction_stack_clearpush_n_ahead(pid, &instruction_stack, regs.rip, 10);
      instruction_tree_insert_n_inst_from_rip_and_push_to_inst_stack(pid, &tree, &instruction_stack, regs.rip, 10);
      instruction_stack_print(&instruction_stack);
      // instructions_print_current(&instructions);
      // instructions_print(&instructions);

      getchar();
    }

    instruction_stack_destroy(&instruction_stack);
    instruction_tree_destroy(&tree);
  }

  return 0;
}
