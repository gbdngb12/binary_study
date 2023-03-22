#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <linux/net.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "branch_pred.h"  //컴파일러가 조건 분기를 예측 할 수 있도록 하는 단서 -> 성능 최적화
#include "libdft_api.h"   //명령어의 call back 삽입 및 관리
#include "pin.H"
#include "syscall_desc.h"  //systemcall 관리
#include "tagmap.h"        //shadow memory 관리

extern syscall_desc_t syscall_desc[SYSCALL_MAX];

/**
 * @brief socket으로 정보를 외부로 부터 수신 받고 그 정보를 오염 시킨다.
 * @param ctx 시스템콜과 관련된 pin 내부 자료구조
 */
void post_socketcall_hook(syscall_ctx_t *ctx);

/**
 * @brief socket으로 수신받은 오염된 정보가 execve함수로 넘어 오는지 확인한다.
 * @param ctx 시스템콜과 관련된 pin 내부 자료구조
 */
void pre_execve_hook(syscall_ctx_t *ctx);

/**
 * @brief taint sink(오염 지역)에 오염이 발생한 경우 경고후 프로그램 종료
 * @param addr 오염된 정보의 주소
 * @param source 추가 정보(어디서 왔는지)
 * @param taint 오염 정보
 */
void alert(uintptr_t addr, const char *source, uint8_t taint);

/**
 * @brief 현재 데이터가 오염됐는지 분석한다. 오염 됐다면 alert 함수를 호출한다.
 * @param str 오염됐는지 분석할 정보
 * @param source 추가 정보(어디서 왔는지)
 */
void check_string_taint(const char *str, const char *source);

void alert(uintptr_t addr, const char *source, uint8_t taint) {
    fprintf(stderr, "\n(dta-execve) !!!!!! ADDRESS 0x%x IS TAINTED (%s, taint=0x%02x), ABORTING !!!!!!!\n", addr, source, taint);
    exit(1);
}

void check_string_taint(const char *str, const char *source) {
    uint8_t taint;
    uintptr_t start = (uintptr_t)str;
    uintptr_t end = (uintptr_t)str + strlen(str);

    fprintf(stderr, "(dta-execve) checking taint on bytes 0x%x -- 0x%x (%s)...", start, end, source);

    for (uintptr_t addr = start; addr <= end; addr++) {
        taint = tagmap_getb(addr);  // get the tag value of a byte from the tagmap
        if (taint != 0) alert(addr, source, taint);
    }

    fprintf(stderr, "OK\n");
}

void post_socketcall_hook(syscall_ctx_t *ctx) {
    // socketcall(int call, unsigned long *args)
    // Linux 4.3 이전에 사용하던 함수
    int fd;
    void *buf;
    size_t len;

    int syscall_number = (int)ctx->arg[SYSCALL_ARG0];               // Get Systemcall number
    unsigned long *args = (unsigned long *)ctx->arg[SYSCALL_ARG1];  // Get Args

    switch (syscall_number) {
        case SYS_RECV:
            [[__fallthrough__]];
        case SYS_RECVFROM:
            if (unlikely(ctx->ret <= 0)) {  // 오류인 경우
                return;
            }

            fd = (int)args[0];       // file descriptor
            buf = (void *)args[1];   // buf data
            len = (size_t)ctx->ret;  // set recv length

            fprintf(stderr, "(dta-execve) recv: %zu bytes from fd %u\n", len, fd);

            for (size_t i = 0; i < len; i++) {
                if (isprint(((char *)buf)[i])) {
                    fprintf(stderr, "%c", ((char *)buf)[i]);
                } else {
                    fprintf(stderr, "\\x%02x", ((char *)buf)[i]);
                }
            }
            fprintf(stderr, "\n");

            fprintf(stderr, "(dta-execve) tainting bytes %p -- 0x%x with taint 0x%x\n", buf, (uintptr_t)buf + len, 0x01);

            // recv로 받은 모든값을 1로 오염시킨다.
            tagmap_setn((uintptr_t)buf, len, 0x01);  // tag an arbitrary number of bytes in the virtual address space
            break;
        default:
            break;
    }
}

void pre_execve_hook(syscall_ctx_t *ctx) {
    // execve(const char *pathname, char *const argv[],
    //               char *const envp[]);
    const char *filename = (const char *)ctx->arg[SYSCALL_ARG0];  // Get pathname
    char *const *argv = (char *const *)ctx->arg[SYSCALL_ARG1];    // Get argv

    char *const *envp = (char *const *)ctx->arg[SYSCALL_ARG2];  // Get envp

    fprintf(stderr, "(dta-execve) execve: %s (@%p)\n", filename, filename);

    check_string_taint(filename, "execve command");//file name에 오염 정보가 있는지 확인한다.
    while(argv && *argv) {//execve의 나머지 매개변수 검사
        fprintf(stderr, "(dta-execve) arg: %s (@%p)\n", *argv, *argv);
        check_string_taint(*argv, "execve argument");
        argv++;
    }
    while(envp && *envp) {//환경변수 매개변수 검사
        fprintf(stderr, "(dta-execve) env: %s (@%p)\n", *envp, *envp);
        check_string_taint(*envp, "execve environment parameter");
        envp++;
    }
}

int main(int argc, char **argv) {
    PIN_InitSymbols();                     // Pin의 심벌 정보 초기화
    if (unlikely(PIN_Init(argc, argv))) {  // 실패 할 거 같지 않다. 분기 예측 도움 -> 실행 성능 향상
        return 1;
    }

    if (unlikely(libdft_init() != 0)) {  // libdft 초기화
        libdft_die();                    // libdft가 할당했던 모든 자원을 해제 하고 종료
        return 1;
    }

    syscall_set_post(&syscall_desc[__NR_socketcall /*socketcall syscall number*/],
                     post_socketcall_hook /*hooking function pointer*/);  // syscall이 호출 되기 이전에 콜백 함수를 호출한다.
    syscall_set_pre(&syscall_desc[__NR_execve /*execve syscall number*/],
                    pre_execve_hook /*hooking function pointer*/);  // syscall이 호출되고 난후 콜백 함수를 호출한다.

    // 특정 명령어를 hooking 하는 방법
    /* ins descriptors */
    // extern ins_desc_t ins_desc[XED_ICLASS_LAST];
    // ins_set_post(&ins_desc[XED_ICLASS_RET_NEAR], dta_instrument_ret);//XED_ICLASS_RET_NEAR(니모닉과 관련)의 명령어가 호출되기 전에 dta_instrument_ret 콜백함수 호출
    // https://intelxed.github.io/ref-manual/

    PIN_StartProgram();

    return 0;  // 절대 실행 되지 않음
}