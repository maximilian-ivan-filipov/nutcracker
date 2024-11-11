#ifndef UTILS_H_
#define UTILS_H_

#include <stdio.h>
#include <stdlib.h>

#define panic(fmt, ...)                                                        \
  do {                                                                         \
    fprintf(stderr, fmt, ##__VA_ARGS__);                                       \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

#endif // UTILS_H_
