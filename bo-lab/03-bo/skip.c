#include<stdio.h>

void function (int a, int b, int c) {
    int *ret=NULL;
    char buffer[16];
    ret = (int *)(buffer+40);
    (*ret) += 1;
}

int main() {
    int x;
    x = 0;
    function (1,2,3);
    x = 1;
    printf("Value of x is %d\n", x);
    return 0;
}
