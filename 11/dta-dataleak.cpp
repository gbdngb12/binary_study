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

#include <map>
#include <string>

#include "branch_pred.h"
#include "libdft_api.h"
#include "pin.H"
#include "syscall_desc.h"
#include "tagmap.h"

extern syscall_desc_t syscall_desc[SYSCALL_MAX];
std::map<int, uint8_t> fd_to_color;
std::map<uint8_t, std::string> color_to_fname;
const int max_color = 0x80;

/**
 * @brief taint sink(오염 지역)에 오염이 발생한 경우 경고후 프로그램 종료
 * @param addr 오염된 정보의 주소
 * @param taint 오염 정보
 */
void alert(uintptr_t addr, uint8_t taint);

/**
 * @brief 현재 데이터가 오염됐는지 분석한다. 오염 됐다면 alert 함수를 호출한다.
 * @param str 오염됐는지 분석할 정보
 * @param source 추가 정보(어디서 왔는지)
 */
void check_string_taint(const char *str, const char *source);

/**
 * @brief open 함수가 호출된 후 open한 fd에 대한 color를 관리한다.
 * @param ctx pin syscall ctx
 */
void post_open_hook(syscall_ctx_t *ctx);

/**
 * @brief read 함수가 호출된 후 read한 내용을 오염시킨다.(taint source)
 * @param ctx pin syscall ctx
 */
void post_read_hook(syscall_ctx_t *ctx);

/**
 * @brief 오염 지역(taint sink) 오염된 파일이 네트워크를 통해 외부로 나가는지 확인한다.
 * @param ctx pin syscall ctx
 */
void pre_socketcall_hook(syscall_ctx_t *ctx);

void alert(uintptr_t addr, uint8_t taint) {
    fprintf(stderr, "\n(dta-dataleak) !!!!! ADDRESS 0x%x IS TAINTED (taint=0x%02x), ABORTING !!!!!\n", addr, taint);

    for (unsigned char c = 0x01; c <= max_color; c <<= 1) {
        if (taint & c) {
            fprintf(stderr, "  tainted by color = 0x%02x (%s)\n", c /*오염 색깔*/, color_to_name[c].c_str() /*오염 파일 이름*/);
        }
    }
    exit(1);
}

void post_open_hook(syscall_ctx_t *ctx) {
    // int open(const char *pathname, int flags);
    static uint8_t next_color = 0x01;
    uint8_t color;
    int fd = (int)ctx->ret;
    const char *fname = (const char *)ctx->arg[SYSCALL_ARG0];

    if (unlikely((int)ctx->ret < 0)) {
        return;
    }

    if (strstr(fname, ".so") || strstr(fname, ".so.")) {  // if opened file is shared library
        return;                                           // do nothing
    }

    fprintf(stderr, "(dta-dataleak) opening %s at fd %u with color 0x%02x\n", fname, fd, next_color);

    if (!fd_to_color[fd]) {  // open한 fd의 오염색깔이 없다면
        color = next_color;
        fd_to_color[fd] = color;                       // 오염색 등록
        if (next_color < max_color) next_color <<= 1;  // max_color보다 크면 오염색은 변하지 않음 -> 1바이트 오염색의 한계점
    } else {
        // open한 fd의 오염 색깔이 있다면 그대로 사용
        color = fd_to_color[fd];
    }

    if (color_to_fname[color].empty()) {             // color에 대한 file name이 비어있다면
        color_to_fname[color] = std::string(fname);  // color에 대한 file name 설정
    } else {                                         // 같은색이 있다면 이름 append(한계점)
        color_to_fname[color] += " | " + std::string(fname);
    }
}

void post_read_hook(syscall_ctx_t *ctx) {
    // ssize_t read(int fd, void *buf, size_t count);
    int fd = (int)ctx->arg[SYSCALL_ARG0];
    void *buf = (void *)ctx->arg[SYSCALL_ARG1];
    size_t len = (size_t)ctx->ret;

    uint8_t color;

    if (unlikely(len <= 0)) {
        return;
    }

    fprintf(stderr, "(dta-dataleak) read: %zu bytes from fd %u\n", len, fd);

    color = fd_to_color[fd];
    if (color) {
        fprintf(stderr, "(dta-dataleak) tainting bytes %p -- 0x%x with color 0x%x\n",
                buf, (uintptr_t)buf + len, color);
        tagmap_setn((uintptr_t)buf, len, color);  // set taint
    } else {                                      // shared library와 같은 fd
        fprintf(stderr, "(dta-dataleak) clearing bytes %p -- 0x%x\n",
                buf, (uintptr_t)buf + len);
        tagmap_clrn((uintptr_t)buf, len);  // tainting clear
    }
}

void pre_socketcall_hook(syscall_ctx_t *ctx) {
    // int socketcall(int call, unsigned long *args);
    int fd;
    void *buf;
    size_t i, len;
    uint8_t taint;
    uintptr_t start, end, addr;

    int call = (int)ctx->arg[SYSCALL_ARG0];
    unsigned long *args = (unsigned long *)ctx->arg[SYSCALL_ARG1];

    switch (call) {
        case SYS_SEND:
        case SYS_SENDTO:
            fd = (int)args[0];
            buf = (void *)args[1];
            len = (size_t)args[2];

            fprintf(stderr, "(dta-dataleak) send: %zu bytes to fd %u\n", len, fd);

            for (i = 0; i < len; i++) {
                if (isprint(((char *)buf)[i])) {
                    fprintf(stderr, "%c", ((char *)buf)[i]);
                } else {
                    fprintf(stderr, "\\x%02x", ((char *)buf)[i]);
                }
            }

            fprintf(stderr, "(dta-dataleak) checking taint on bytes %p -- 0x%x...", buf, (uintptr_t)buf + len);
            start = (uintptr_t)buf;
            end = (uintptr_t)buf + len;

            for (addr = start; addr <= end; addr++) {
                taint = tagmap_getb(addr);
                if (taint != 0) alert(addr, taint);
            }
            fprintf(stderr, "OK\n");

            break;
        default:
            break;
    }
}

int main(int argc, char **argv) {
    PIN_InitSymbols();  // Pin Symbol 정보 초기화

    if (unlikely(PIN_Init(argc, argv))) {
        return 1;
    }

    if (unlikely(libdft_init() != 0)) {
        libdft_die();
        return 1;
    }

    syscall_set_post(&syscall_desc[__NR_open], post_open_hook);            // open 함수가 호출된 후 그 파일을 오염시킨다.
    syscall_set_post(&syscall_desc[__NR_read], post_read_hook);            // read 함수가 호출된 후 오염 됐는지 확인한다.
    syscall_set_pre(&syscall_desc[__NR_socketcall], pre_socketcall_hook);  // socketcall 함수로 외부로 나가기 전에 오염 지역을 확인한다.

    PIN_StartProgram();
    return 0;
}