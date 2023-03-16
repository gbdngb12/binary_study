#pragma once
#include <capstone/capstone.h>
#include <stdio.h>

#include <string>

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