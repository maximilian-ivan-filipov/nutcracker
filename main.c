
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

    // stack which pushes future instructions into next stack
    // and previous instructions into prev stack
    // which alloows for super easy time travel
    // the stack "tops" are the last element so when we want to go 
    // backwards in time, we just pop the prev stack and push
    // to the next stack, vice versa, i know its weird a queue would 
    // be more intuitive but it is what it is.
    struct InstructionStack prev_inst_stack;
    struct InstructionStack next_inst_stack;
    struct InstructionStack lookahead_inst_stack;

    instruction_stack_init(&prev_inst_stack);
    instruction_stack_init(&next_inst_stack);
    instruction_stack_init(&lookahead_inst_stack);

    struct Instruction *current_instruction = NULL;

    while (1) {

        registers_read(&regs, pid);
        registers_print(&regs);

        size_t bytes_read;
        struct Instruction *inst =
            instruction_read(pid, regs.rip, &bytes_read);
        if (!inst) continue;

        struct InstructionData *data = instruction_data_create(inst, &regs);
        if (!data) continue;

        instruction_tree_insert(&tree, regs.rip, data);
        instruction_tree_insert_push_lookahead(pid, &tree, &lookahead_inst_stack, regs.rip, 5);
        // add instruction_stack_back()

        instruction_stack_print("Previous", &prev_inst_stack);
        instruction_stack_print("Next", &next_inst_stack);
        instruction_stack_print("Lookahead", &lookahead_inst_stack);

        instruction_stack_push(&prev_inst_stack, data);
        process_singlestep(pid);




      //instruction_stack_push(&instruction_stack, data);
      //instruction_stack_print(&instruction_stack);

      /*struct InstructionData *content = NULL;*/
      /*instruction_tree_find(&tree, regs.rip, &content);*/
      /*if (content) {*/
      /*  printf("[%ld] = %s %s\n", content->inst->address,*/
      /*         content->inst->mnemonic, content->inst->ops);*/
      /*  fflush(stdout);*/
      /*}*/
      /*struct Instruction *instruction = NULL;*/
      /*instruction_tree_find_as_instruction(&tree, regs.rip, &instruction);*/
      /*instruction_print(instruction);*/

      // lookahead n next instruction and save to tree and lookahead stack
      // just for visuals, registers should be NULL, since those instructions
      // are not yet executed
      // instructions_print_current(&instructions);
      // instructions_print(&instructions);

      getchar();
    }

    instruction_stack_destroy(&prev_inst_stack);
    instruction_stack_destroy(&next_inst_stack);
    instruction_stack_destroy(&lookahead_inst_stack);
    instruction_tree_destroy(&tree);
  }

  return 0;
}
