#include <stdio.h>
#include <string.h>

int copier(char *str) {
    char buffer[5];
    strcpy(buffer, str);
    return 0;
}

int main(void) {
    char input[100];
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;
    copier(input);
    printf("Completed Execution Successfully!\n");
    return 0;
}

