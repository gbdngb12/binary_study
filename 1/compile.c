#include <stdio.h>

#define FORMAT_STRING "%s"
#define MESSAGE "Hello, world!\n"

int main() {
    printf(FORMAT_STRING, MESSAGE);
    printf(FORMAT_STRING, MESSAGE);
    return 0;
}
