#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int overlapping(int i) {
    int j = 0;

    __asm__ __volatile__(
        "cmp   $0x0,%1         ; "
        ".byte 0x0f,0x85       ; " /* relative jne */
        ".long 2               ; " /* jne offset   */
        "xorl  $0x04,%0        ; "
        ".byte 0x04,0x90       ; " /* add al,0x90  */
        : "=r"(j)//%0
        : "r"(i)//%1
        :);

    return j;
}

int main(int argc, char *argv[]) {
    srand(time(NULL));
    printf("%d\n", overlapping(rand() % 2));

    return 0;
}
