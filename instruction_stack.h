

#include "data.h"
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
    if (stack->size == INSTRUCTION_STACK_CAPACITY) {
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
    struct InstructionData *data = stack->stack[stack->size-1];
    stack->size--;
    return data;
}

struct Instruction *instruction_stack_pop_as_instruction(struct InstructionStack *stack) {
    struct InstructionData *data = instruction_stack_pop(stack);
    struct Instruction *instruction = data->inst;
    return instruction;
}

size_t instruction_stack_size(struct InstructionStack *stack) {
    if (!stack) {
        return 0;
    }
    return stack->size;
}

void instruction_stack_print(struct InstructionStack *stack) {
    if (!stack) {
        puts("instruction stack is empty!\n");
    }
    printf("Instruction_Stack[%ld]:\n", instruction_stack_size(stack));
    for (size_t i = 0; i < instruction_stack_size(stack); i++) {
        struct InstructionData *data = stack->stack[i];
        instruction_print(data->inst);
    }
}


void instruction_stack_destroy(struct InstructionStack *stack) {
    for (int i = 0; i < INSTRUCTION_STACK_CAPACITY; i++) {
        free(stack->stack[i]);
        stack->stack[i] = NULL;
    }
    stack->size = 0;
}

void instruction_stack_clear(struct InstructionStack *stack) {
    if (!stack) {
        return;
    }
    instruction_stack_destroy(stack);
}

/*void instruction_stack_clearpush_n_ahead(pid_t pid, struct InstructionStack *stack, long address, int n) {*/
/*    instruction_stack_clear(stack);*/
/*    size_t offset = 0;*/
/*    size_t bytes_read = 0;*/
/*    for (int i = 0; i < n; i++) {*/
/*        struct Instruction *instruction =  instruction_read(pid, address + offset, &bytes_read);*/
/*        if (instruction) {*/
/*            struct InstructionData* data = instruction_data_create(instruction, NULL);*/
/*            instruction_stack_push(stack, data);*/
/*        }*/
/*        offset += bytes_read;*/
/*        bytes_read = 0;*/
/*    }*/
/*}*/
/**/

