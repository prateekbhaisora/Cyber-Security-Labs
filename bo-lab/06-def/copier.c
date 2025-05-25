#include<stdio.h>
#include<string.h>

int copier(char *str) {
    char buffer[5];
    strcpy(buffer, str);
}

int main(int argc, char* argv[]) {
    copier(argv[1]);
    printf("Completed Execution Successfully!\n");
}
