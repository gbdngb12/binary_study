#pragma once
#include <capstone/capstone.h>
#include <stdio.h>
#include <string>
#include <queue>
#include <map>

#include "loader.h"

namespace disas {
enum class Type {
    LINEAR,
    RECURSIVE
};
}

/**
 * @brief Binary를 디스어셈블한다.
 * @param bin disassemble할 바이너리 클래스
 * @param disas_type disassemble 할 타입(선형, 재귀)
 * @return 성공시 0 / 실패시 -1
 */
int disasm(Binary* bin, disas::Type disas_type);

/**
 * @brief 명령어를 보기좋게 출력한다.
 * @param ins 캡스톤 명령어 자료구조
*/
void print_ins(cs_insn *ins);

/**
 * @brief jump, call, ret, interrupt인지 확인한다.
 * @param g 명령어의 그룹 타입
 * @return true / false
*/
bool is_cs_cflow_group(uint8_t g);

/**
 * @brief 명령어를 가지고 branch(call, ret, jump, interrupt)인지 확인한다.
 * @param ins 캡스톤 명령어 자료구조
 * @return true / false
*/
bool is_cs_cflow_ins(cs_insn *ins);

/**
 * @brief 명령어를 가지고 조건이 없는 immediate branch인지 확인한다.
 * @param ins 캡스톤 명령어 자료구조
 * @return true / false
*/
bool is_cs_unconditional_cflow_ins(cs_insn *ins);

/**
 * @brief 조건이 없는 immediate branch(jump, call, ret interrupt)의 target 주소를 가져온다.
 * @param ins 캡스톤 명령어 자료구조
 * @return true / false
*/
uint64_t get_cs_ins_immediate_target(cs_insn *ins);