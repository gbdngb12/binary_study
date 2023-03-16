#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void* (*orig_malloc)(size_t);              // orignal malloc function pointer
void (*orig_free)(void*);                  // orignal free function pointer
char* (*orig_strcpy)(char*, const char*);  // orignal strcpy function pointer

typedef struct {
    uintptr_t addr;
    size_t size;
} alloc_t;  //관리할 malloc으로 할당된 멤버 구조체

#define MAX_ALLOCS 1024

alloc_t allocs[MAX_ALLOCS];  //관리할 malloc으로 할당된 멤버 구조체 배열
unsigned alloc_idx = 0;

void* malloc(size_t s) {
    if (!orig_malloc) orig_malloc = dlsym(RTLD_NEXT, "malloc");  // get shared Library malloc address

    void* ptr = orig_malloc(s); //call orignal malloc
    if (ptr) {
        allocs[alloc_idx].addr = (uintptr_t)ptr;
        allocs[alloc_idx].size = s;
        alloc_idx = (alloc_idx + 1) % MAX_ALLOCS;
    }

    return ptr;
}

void free(void* p) {
    if(!orig_free) orig_free = dlsym(RTLD_NEXT, "free");// get shared Library free address

    orig_free(p); //call orignal free

    for(unsigned i = 0; i < MAX_ALLOCS; i++) {
        if(allocs[i].addr == (uintptr_t)p) { //구조체 삭제 작업
            allocs[i].addr = 0;
            allocs[i].size = 0;
            break;
        }
    }
}

char* strcpy(char* dst,const char *src) {
    if(!orig_strcpy) orig_strcpy = dlsym(RTLD_NEXT, "strcpy"); // get shared Library strcpy address

    for(unsigned i = 0; i < MAX_ALLOCS; i++) {//만약 1024개 이상 malloc해서 일치하는게 없을수도! 실전코드는 좀더 정교하게
        if(allocs[i].addr == (uintptr_t)dst) { //구조체중에서 목적지가 일치하는곳에서!
            if(allocs[i].size <= strlen(src)) { //src의 길이가 malloc에 할당된것과 같다면
                printf("Bad idea! Aborting strcpy to prevent heap overflow\n");
                exit(1);
            }
            break;
        }
    }

    return orig_strcpy(dst, src);
}