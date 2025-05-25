#include <string.h>
#include <stdio.h>
#include <unistd.h>

void first64(char *str) {
  char buffer[64];
  memcpy(buffer, str, 100);
}

int main(int argc, char **argv) {
  static char input[1024];
  read(STDIN_FILENO, input, 1024);
  first64(input);
  return 0;
}
