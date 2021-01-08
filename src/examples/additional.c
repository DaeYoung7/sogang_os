#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  int i, nums[4];
  for (i = 1; i < argc; i++) nums[i-1] = atoi(argv[i]);
  printf ("%d %d\n", fibonacci(nums[0]), max_of_four_int(nums[0], nums[1], nums[2], nums[3]));
  return EXIT_SUCCESS;
}
