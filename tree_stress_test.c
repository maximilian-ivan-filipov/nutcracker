
#include "data.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct Test {
  int i;
  long key;
  long data;
};
struct InstructionTree tree;

long generate_random_long() {
  long random_value = (long)(((long)rand() << 48) | ((long)rand() << 32) |
                             ((long)rand() << 16) | ((long)rand()));

  if (random_value < 0) {
    random_value *= -1;
  }

  return random_value;
}

int test(int i, long key, long data) {
  instruction_tree_insert(&tree, key, data);
  long control;
  instruction_tree_find(&tree, key, &control);
  if (control == data) {
    printf("[%d] : passed: key[%20ld] -> value[%20ld]\n", i, key, data);
    return 0;
  } else {
    printf("[%d] : key[%ld] -> value[%ld] ... FAILED\n", i, key, data);
    return i;
  }
}

#define RANGE 1000000000000

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("usage ./tree_stress_test <number of tests>\n");
    exit(EXIT_SUCCESS);
  }

  srand(time(NULL));

  struct Test **tests = calloc(atoi(argv[1]), sizeof(struct Test));
  if (!tests) {
    panic("calloc failed");
  }
  int test_size = 0;

  instruction_tree_init(&tree);

  int i;
  for (i = 0; i < atoi(argv[1]); i++) {
    long key = generate_random_long();
    long data = generate_random_long();
    int ret = test(i, key, data);
    if (ret != 0) {
      tests[test_size] = (struct Test *)calloc(1, sizeof(struct Test));
      tests[test_size]->i = ret;
      tests[test_size]->data = data;
      tests[test_size]->key = key;
      test_size++;
    }
  }
  if (test_size == 0) {
    printf("### All %d tests passed.\n", i);
  } else {
    if (tests) {
      for (int i = 0; i < test_size; i++) {
        printf("\t[%d] : failed key [%20ld] -> value [%20ld]\n", tests[i]->i,
               tests[i]->key, tests[i]->data);
      }
      printf("%d Tests failed!\n", test_size);
    } else {
      panic("flags is somehow NULL\n");
    }
  }

  for (int i = 0; i < test_size; i++) {
    free(tests[i]);
  }
  free(tests);
  instruction_tree_destroy(&tree);
}
