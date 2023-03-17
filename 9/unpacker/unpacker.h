#pragma once
#include "pin.H"
#include <cstdio>
#include <map>
#include <vector>
#include <string>

/**
 * @struct memory Access 정보
 * 메모리 사용 내역
 */
typedef struct mem_access {
    mem_access() : w(false), x(false), val(0) {}
    mem_access(bool ww, bool xx, unsigned char v) : w(ww), x(xx), val(v) {}
    bool w;            /** @brief write*/
    bool x;            /** @brief execute*/
    unsigned char val; /** @brief value*/
} mem_access_t;

/**
 * @brief dump할 Memory cluster 정보
 */
typedef struct mem_cluster {
    mem_cluster() : base(0), size(0), w(false), x(false) {}
    mem_cluster(ADDRINT b, unsigned long s, bool ww, bool xx)
        : base(b), size(s), w(ww), x(xx) {}
    ADDRINT base; /** @brief base Address*/
    unsigned long size; /** @brief Memory cluster size*/
    bool w; /** @brief write*/
    bool x; /** @brief execute*/
} mem_cluster_t;

FILE *logfile; /** @brief cluster를 기록할 로그 파일*/
std::map<ADDRINT /*주소*/, mem_access_t/*memory cluster 정보*/> shadow_mem; /** @brief 어떤 메모리주소에 대한 접근 정보 저장*/
std::vector<mem_cluster_t> clusters;/** @brief OEP로 추정되는 memory cluster vector*/
ADDRINT saved_addr; /** @brief 메모리 쓰게 작업시에는 쓰기 작업 이후에 그 값을 읽어 올 수 있기 때문에, 시작 지점을 미리 저장 해놓아야함*/

/**
 * @brief intel pin에서 제공하는 커맨드 라인 옵션 객체 : 로그파일 위치 및 이름 설정
*/
KNOB<std::string> KnobLogFile(KNOB_MODE_WRITEONCE, "pintool", "l", "unpacker.log", "log file");

/**
 * @brief 파일의 크기를 string으로 변환
 * @param size 파일의 크기 값
 * @param buf string buf
 * @param len string len
*/
void fsize_to_str(unsigned long size, char *buf, unsigned len);

/**
 * @brief cluster, entry_point 정보를 파일로 저장한다.
 * @param c 메모리 cluster
 * @param entry entry point
*/
void mem_to_file(mem_cluster_t *c, ADDRINT entry);

/**
 * @brief 
 * @param target
 * @param c
*/
void set_cluster(ADDRINT target, mem_cluster_t *c);

/**
 * @brief 
 * @param target 
 * @return 
*/
bool in_cluster(ADDRINT target);

/**
 * @brief
 * @param c
 * @param d
 * @return 
*/
bool cmp_cluster_size(const mem_cluster_t &c, const mem_cluster_t &d);

/**
 * @brief 메모리에 저장된 OEP cluster 정보를 출력한다.
*/
void print_clusters();

/**
 * @brief 가장 마지막에 실행되는 콜백 함수
 * @param code exit code
 * @param v 사용자 정의 자료구조
*/
void fini(INT32 code /*exit code*/, void *v /*사용자 정의 자료구조*/);

/**
 * @brief 메모리 쓰기 작업시의 시작 주소 저장
 * @param addr 메모리 쓰기 작업시의 시작 주소
*/
void queue_memwrite(ADDRINT addr);

/**
 * @brief 메모리 쓰기 작업시의 분석 루틴
 * 쓰기 한 값을 읽어온다.
 * @param size 쓰기 한 크기
*/
void log_memwrite(UINT32 size);

/**
 * @brief 간접 제어 목적지가 이전에 메모리 쓰기 한값이 있었는지 확인한다.
 * 즉, OEP인지 확인한다. 
 * @param start_address 간접 제어 시작 주소 
 * @param target 간접 제어 목적지 도착지 주소
*/
void check_indirect_ctransfer(ADDRINT start_address, ADDRINT target);

/**
 * @brief 명령어 계측 루틴
 * 모든 명령어 계측 수행
 * 2. 모든 메모리 쓰기 작업 검사 및 값 저장
 *  (1) fall through이면서 쓰기 작업 : mov [rbp + 0x40], 0x1234 ; 0x1234 저장
 *  (2) taken branch이면서 쓰기 작업 : cmov [rbp + 0x40], 0x3456 ; 0x3456 저장
 * 3. 모든 직.간접호출 검사
 *  (1) 2번에서 저장한 값으로 가는지 확인
 *  (2) 2번에서 저장한 값으로 taken이면 OEP일 가능성 존재
 * @param ins 명령어
 * @param v 사용자 정의 자료구조
*/
void instrument_mem_cflow(INS ins /*명령어*/, void *v /*사용자 정의 자료구조*/);