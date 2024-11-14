#ifndef DATA_H_
#define DATA_H_

#include "instruction.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>

// forward declaration of used structs and functions
struct InstructionStack;
struct InstructionData *instruction_stack_push(struct InstructionStack *stack, struct InstructionData* _instruction);
void instruction_stack_clear(struct InstructionStack *stack);

/* digit based tree, to map instruction pointer addresses (eg 0x12345678) to
 * information about states in this instrucition like registers, open fd's and
 * other info, thus we can time travel easily path taken by % 10, O(d) where d
 * is the depth thus for # 32 Bit Decimal -> d = 10, Hexadecimal -> d = 8 # 64
 * Bit Decimal     -> d = 20 Hexadecimal -> d = 16
 * */

// Decimal 64 bit version for now
//
//
//
#define LEAFS_LEN 10

struct InstructionNode {
  struct InstructionNode *leafs[LEAFS_LEN];
  struct InstructionData *data;
};

struct InstructionTree {
  struct InstructionNode *dummy;
  int size;
};

void instruction_tree_init(struct InstructionTree *tree) {
  if (!tree) {
    panic("instruction_tree_init: tree is NULL\n");
  }
  tree->dummy = calloc(1, sizeof(struct InstructionNode));
  if (!tree->dummy) {
    panic("instruction_tree_init: calloc failed\n");
  }
}

// ###########################################

void instruction_tree_find_recursive(struct InstructionNode *node, long key,
                                     struct InstructionData **data) {
  if (!node) {
    *data = NULL;
    return;
  }

  // data found!
  if (key == 0) {
    *data = node->data;
    return;
  }

  int digit = key % 10;
  key /= 10;

  if (key == 0 && digit == 0) {
    *data = node->data;
    return;
  }
  instruction_tree_find_recursive(node->leafs[digit], key, data);
}

void instruction_tree_find(struct InstructionTree *tree, long key,
                           struct InstructionData **data) {
  if (!tree) {
    panic("instruction_tree_find: tree is NULL\n");
  }
  instruction_tree_find_recursive(tree->dummy, key, data);
}

void instruction_tree_find_as_instruction(struct InstructionTree *tree, long key, struct Instruction **instruction) {
    struct InstructionData *data = NULL;
    instruction_tree_find(tree, key, &data);
    *instruction = data->inst;
}

// ###########################################3

void instruction_tree_insert_recursive(struct InstructionNode *node, long key,
                                       struct InstructionData *data) {
  if (!node) { // should never happen
    panic("instruction_tree_insert_recursive: node is NULL, pretty bad\n");
  }

  if (key == 0) {
    node->data = data;
    return;
  }

  int digit = key % 10;
  key /= 10;

  if (node->leafs[digit] == NULL) {
    node->leafs[digit] = calloc(1, sizeof(struct InstructionNode));
    if (!node->leafs[digit]) {
      panic("instruction_tree_insert_recursive: calloc failed\n");
    }
  }
  instruction_tree_insert_recursive(node->leafs[digit], key, data);
}
void instruction_tree_insert(struct InstructionTree *tree, long key,
                             struct InstructionData *data) {
  if (!tree || !data) {
      return;
  }
  instruction_tree_insert_recursive(tree->dummy, key, data);
}

// ###########################################3
// fill instruction tree and hashmap, instruction tree for fast access of data and instruction stack is for
// showing just the next n instructions ahead for convienience, n max is defined currently as 32 
// look for INSTRUCTION_STACK_CAPACITY, changing it will not break anything
// We do not have meaningful register values and set them to nil, since we just LOOKAHEAD and dont execute instruction
// later if we reach that instruction we should update the tree with the new registers, with 
// instruction_tree_insert(...), so we can have easy lookahead anytime
int instruction_tree_insert_push_lookahead(pid_t pid, struct InstructionTree *tree, struct InstructionStack *stack, long start_address, int n) {
    instruction_stack_clear(stack);
    size_t offset = 0;
    size_t bytes_read = 0;

    for (int i = 0; i < n; i++) {
        long key = start_address + offset;
        struct Instruction *instruction =  instruction_read(pid, key, &bytes_read);
        struct InstructionData* data = instruction_data_create(instruction, NULL);
        if (instruction) {
            struct InstructionData * previous_data;
            instruction_tree_find(tree, key, &previous_data);
            // overwrite instruction in tree if register were NULL
            // so we dont overwrite already executed instructions
            if (!previous_data || (previous_data && previous_data->regs == NULL)) {
                instruction_tree_insert(tree, key, data);
            }
        }
        instruction_stack_push(stack, data);

        offset += bytes_read;
        bytes_read = 0;
    }
    return -1;
}

void instruction_tree_delete_recursive(struct InstructionNode *node) {
  if (!node) {
    return;
  }
  for (int i = 0; i < LEAFS_LEN; i++) {
    instruction_tree_delete_recursive(node->leafs[i]);
  }
  free(node);
}

void instruction_tree_destroy(struct InstructionTree *tree) {
  if (tree) {
    instruction_tree_delete_recursive(tree->dummy);
  }
}

#endif // DATA_H_
