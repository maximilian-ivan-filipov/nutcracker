#ifndef INSTRUCTION_H_
#define INSTRUCTION_H_

#include "utils.h"
#include <capstone/capstone.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>

#define INSTRUCTION_SIZE 15

struct Instruction {
  long address;
  char mnemonic[8];
  char ops[32];
};

struct Instructions {
  struct Instruction *instructions;
  size_t size;
  size_t capacity;
};

void instruction_print(struct Instruction *instruction) {
  if (!instruction) {
    panic("instruction_print: instruction is NULL\n");
  }
  printf("[0x%lx] %s %s\n", instruction->address, instruction->mnemonic,
         instruction->ops);
}

void instructions_print_current(struct Instructions *instructions) {
  if (!instructions) {
    panic("instruction_print_current: instructions is NULL\n");
  }
  instruction_print(&instructions->instructions[instructions->size - 1]);
}

void instructions_print(struct Instructions *instructions) {
  if (!instructions) {
    panic("instructions_print: instructions is NULL\n");
  }
  printf("######################\n");
  for (size_t i = 0; i < instructions->size; i++) {
    instruction_print(&instructions->instructions[i]);
  }
  printf("######################\n");
}

long memory_read(pid_t pid, unsigned long address) {
  int mem = ptrace(PTRACE_PEEKDATA, pid, (void *)address, NULL);
  if (mem == -1) {
    panic("could not read memery at address = %ld\n", address);
  }
  return mem;
}

unsigned char *instruction_fetch(pid_t pid, long address) {
  long data1 = memory_read(pid, address);
  long data2 = memory_read(pid, address + sizeof(long));
  unsigned char *buffer = malloc(INSTRUCTION_SIZE * sizeof(char));
  if (!buffer) {
    return NULL;
  }
  memcpy(buffer, &data1, sizeof(long));
  memcpy(buffer + sizeof(long), &data2, sizeof(long) - 1);
  return buffer;
}

int instructions_add(struct Instructions *instructions,
                     struct Instruction *instruction) {
  if (!instructions || !instruction) {
    return -1;
  }
  if (instructions->size >= instructions->capacity) {
    instructions->instructions =
        realloc(instructions->instructions, instructions->size + 50);
    instructions->capacity += 50;
  }
  memcpy(&instructions->instructions[instructions->size++], instruction,
         sizeof(struct Instruction));
  return 0;
}

int instructions_push(struct Instructions *instructions, unsigned char *data,
                      long address) {

  csh handle;
  cs_insn *insn;
  size_t count;

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    return -1;
  // changed to only disassembly 1 byte ( maybe it works, need to see )
  count = cs_disasm(handle, data, INSTRUCTION_SIZE, address, 1, &insn);
  if (count > 0) {
    size_t j;
    for (j = 0; j < count; j++) {

      struct Instruction instruction;
      instruction.address = insn[j].address;

      strncpy(instruction.mnemonic, insn[j].mnemonic,
              sizeof(instruction.mnemonic) - 1);
      instruction.mnemonic[sizeof(instruction.mnemonic) - 1] = '\0';

      strncpy(instruction.ops, insn[j].op_str, sizeof(instruction.ops) - 1);
      instruction.ops[sizeof(instruction.ops) - 1] = '\0';

      instructions_add(instructions, &instruction);
    }
    // instructions_print(instructions);

    cs_free(insn, count);
  } else
    printf("ERROR: Failed to disassemble given code!\n");

  cs_close(&handle);

  return 0;
}

void instructions_read(pid_t pid, struct Instructions *instructions,
                       long address) {
  unsigned char *bytes = instruction_fetch(pid, address);
  if (!bytes) {
    panic("instructions_read: bytes is NULL\n");
  }
  if (instructions_push(instructions, bytes, address) == -1) {
    panic("instruction_push: could not convert data at address %ld to "
          "instruction\n",
          address);
  }
  free(bytes);
}

void instructions_init(struct Instructions *instructions, uint32_t capacity) {
  if (!instructions) {
    panic("instructions is NULL\n");
  }
  instructions->instructions = malloc(capacity * sizeof(struct Instruction));
  if (!instructions->instructions) {
    panic("instructions_init: malloc failed\n");
  }
  instructions->size = 0;
  instructions->capacity = 0;
}

void instructions_destroy(struct Instructions *instructions) {
  if (instructions) {
    free(instructions->instructions);
  }
}

#endif // INSTRUCTION_H_
