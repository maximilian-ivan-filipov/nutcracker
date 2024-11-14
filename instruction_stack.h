

#include "utils.h"
#include <capstone/capstone.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "instruction.h"

#define INSTRUCTION_STACK_CAPACITY 32

struct InstructionStack {
    struct InstructionData *stack[INSTRUCTION_STACK_CAPACITY];
    size_t size;
};

void instruction_stack_init(struct InstructionStack* instruction_stack) {
    memset(instruction_stack, 0, sizeof(struct InstructionStack));
}

struct InstructionData *instruction_stack_push(struct InstructionStack *stack, struct InstructionData* _instruction) {
    if ((stack->size - 1) == INSTRUCTION_STACK_CAPACITY) {
        return NULL;
    }

    struct InstructionData * instruction = calloc(1, sizeof(struct InstructionData));
    memcpy(instruction, _instruction, sizeof(struct InstructionData));

    if (stack->stack[stack->size] != NULL) {
        free(stack->stack[stack->size]);
        stack->stack[stack->size] = NULL;
    }

    stack->stack[stack->size] = instruction;
    stack->size++;
    return instruction;
}

struct InstructionData *instruction_stack_pop(struct InstructionStack *stack) {
    struct InstructionData *instruction = stack->stack[stack->size-1];
    stack->size--;
    return instruction;
}

size_t instruction_stack_size(struct InstructionStack *stack) {
    if (!stack) {
        return 0;
    }
    return stack->size;
}


void instruction_stack_destroy(struct InstructionStack *stack) {
    for (int i = 0; i < INSTRUCTION_STACK_CAPACITY; i++) {
        free(stack->stack[i]);
        stack->stack[i] = NULL;
    }
}

void instruction_stack_clear(struct InstructionStack *stack) {
    if (!stack) {
        return;
    }
    instruction_stack_destroy(stack);
}

