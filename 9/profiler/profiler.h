#pragma once
#include "pin.H"
#include <map>
#include <string>
/**
 * @brief intel pin에서 제공하는 커맨드 라인 옵션 객체 : Function Call Profile
 */
KNOB<bool> ProfileCalls(KNOB_MODE_WRITEONCE /* 오직 한번만 생성*/, "pintool", "c" /*-c*/, "0" /*Default Value*/, "Profile function calls");

/**
 * @brief intel pin에서 제공하는 커맨드 라인 옵션 객체 : Profile System Call
*/
KNOB<bool> ProfileSysCalls(KNOB_MODE_WRITEONCE/* 오직 한번만 생성*/, "pintool", "s"/*-s*/, "0"/*Default Value*/, "Profile syscalls");

std::map<ADDRINT/** @brief to*/, std::map<ADDRINT/** @brief from*/, unsigned long/*count*/>> cflows; /** @brief control flow(branch) count*/
std::map<ADDRINT/*to*/, std::map<ADDRINT/*from*/, unsigned long/*count*/>> calls; /** @brief function call count*/
std::map<ADDRINT/*Address*/, unsigned long /*syscall number*/> syscalls; /** @brief syscall called number*/
std::map<ADDRINT/*Address*/, std::string/*Function Name*/> funcnames;/** @brief if not stripped, function name map*/

unsigned long insn_count = 0; /** @brief 총 명령어의 수*/
unsigned long cflow_count = 0; /** @brief 총 branch 명령어의 수(jne, jmp등)*/
unsigned long call_count = 0; /** @brief 총 함수 호출의 수*/
unsigned long syscall_count = 0; /** @brief 총 syscall 호출 수*/

/**
 * @brief insn_count에 블록내의 총 명령어의 수 n을 더한다. : 계측 코드, 분석 루틴
 * (실제 계측 수행)
 * @param n 블록 내의 총 명령어 수
*/
void count_bb_insns(UINT32 n);

/**
 * @brief cflow_count에 제어 명령어의 수를 더하고, 해당 정보를 저장한다. : 계측 코드, 분석 루틴
 * (실제 계측 수행)
 * @param start_address 출발지 주소
 * @param target 목적지 주소
*/
void count_cflow(ADDRINT start_address, ADDRINT target);

/**
 * @brief call_count에 함수 호출명령어의 수를 더하고 해당 정보를 저장한다. : 계측 코드, 분석 루틴
 * (실제 계측 수행)
 * @param start_address 출발지 주소
 * @param target 목적지 주소
*/
void count_call(ADDRINT start_address, ADDRINT target);

/**
 * @brief syscall_count에 시스템콜 호출수를 더한다. : 계측 코드, 분석 루틴
 * (실제 계측 수행)
 * @param tid Thread id
 * @param ctx 시스템 콜을 구성하는 요소(시스템 콜 번호, 매개변수, 반환 값)
 * @param std 시스템 콜의 호출 규약
 * @param v 사용자 정의 자료구조
*/
void log_syscall(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v);

/**
 * @brief 이미지 단위의 분석 루틴, 계측 코드
 * Image -> Section으로 변환후 Section내의 모든 routine(함수) 계측
 * (실제 계측 수행)
 * @pre 1. 바이너리에 심벌 정보가 포함 되어 있어야함
 * @pre 2. 꼬리 호출등의 최적화가 수행되지 않아야함
 * @param img 실행중인 바이너리의 이미지
 * @param v 사용자 정의 자료구조
*/
void parse_funcsyms(IMG img, void *v);

/**
 * @brief trace단위의 계측 루틴
 * trace -> block 단위로 변환 후 계측 수행 함수 호출
 * (분석 루틴 삽입)
 * @param trace 실행중인 바이너리의 trace
 * @param v 사용자 정의 자료구조
*/
void instrument_trace(TRACE trace, void *v);

/**
 * @brief 블록단위 계측 루틴 : 분석 루틴 콜백 설치
 * (분석 루틴 콜백 설치)
 * @param bb 실행중인 바이너리의 이미지
*/
void instrument_bb(BBL bb);


/**
 * @brief 명령어 단위 계측 루틴
 * (분석 루틴 콜백 설치)
 * @param ins 실행중인 바이너리의 이미지
 * @param v 사용자 정의 자료구조
*/
void instrument_insn(INS ins, void *v);

/**
 * @brief 사용법을 출력하는 함수
*/
void print_usage();

/**
 * @brief 모든 결과를 출력 하는 함수
 * @param code 
 * @param v 사용자 정의 자료구조
*/
void print_results(INT32 code, void *v);