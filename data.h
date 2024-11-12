#ifndef DATA_H_
#define DATA_H_

#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  // struct Data *data;
  long data;
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
                                     long *data) {
  if (!node) {
    *data = -1;
    return;
  }
  if (key == 0) {
    *data = node->data;
  }

  int digit = key % 10;
  key /= 10;

  if (key == 0 && digit == 0) {
    *data = node->data;
    return;
  }
  instruction_tree_find_recursive(node->leafs[digit], key, data);
}

void instruction_tree_find(struct InstructionTree *tree, long key, long *data) {
  if (!tree) {
    panic("instruction_tree_find: tree is NULL\n");
  }
  instruction_tree_find_recursive(tree->dummy, key, data);
}

// ###########################################3

void instruction_tree_insert_recursive(struct InstructionNode *node, long key,
                                       long data) {
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
                             long data) {
  if (!tree) {
    panic("instruction_tree_insert: tree is NULL\n");
  }
  instruction_tree_insert_recursive(tree->dummy, key, data);
}

// ###########################################3

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
