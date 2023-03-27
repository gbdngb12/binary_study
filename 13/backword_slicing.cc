#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <map>
#include <string>
#include <triton/api.hpp>
#include <triton/x86Specifications.hpp>

#include "../inc/loader.h"
#include "disasm_util.h"
#include "triton_util.h"
/**
 * @brief PC를 다루기위해 triton의 아키텍처 정보를 설정한다.
 * @param bin 바이너리 로더로 로드한 바이너리
 * @param api triton api 참조
 * @param ip PC 레지스터 정보
 * @return 성공 / 실패
 */
int set_triton_arch(Binary &bin, triton::API &api, triton::arch::registers_e &ip);

/**
 * @brief 슬라이싱하려는 주소 위치에 도달했을때, 슬라이싱 결과를 출력
 * @param api triton api
 * @param sec binary loader의 section 정보
 * @param slice_addr target slice address
 * @param reg slice하고자하는 register의 id
 * @param regname slice하고자 하는 register의 이름
 */
void print_slice(triton::API &api, Section *sec, uint64_t slice_addr,
                 triton::arch::registers_e reg, const char *regname);

void print_slice(triton::API &api, Section *sec, uint64_t slice_addr,
                 triton::arch::registers_e reg, const char *regname) {
    triton::engines::symbolic::SymbolicExpression *regExpr; /** @brief */
    std::map<triton::usize, triton::engines::symbolic::SymbolicExpression *> slice;
    char mnemonic[32], operands[200];

    regExpr = api.getSymbolicRegisters()[reg];  // 모든 기호 표현식에 대한 레지스터 정보를 가져옴
    slice = api.sliceExpressions(regExpr);      // 해당 레지스터 정보에 영향을 받는 모든 기호 표현식에 대한 정보를 가져온다.

    for (auto &kv : slice) {
        printf("%s\n", kv.second->getComment().c_str());
    }

    disasm_one(sec, slice_addr, mnemonic, operands);
    std::string target = mnemonic;
    target += " ";
    target += operands;

    printf("(slice for %s @ 0x%jx: %s)\n", regname, slice_addr, target.c_str());
}

int set_triton_arch(Binary &bin, triton::API &api, triton::arch::registers_e &ip) {
    if (bin.arch != Binary::BinaryArch::ARCH_X86) {
        fprintf(stderr, "Unsupported architecture\n");
        return -1;
    }

    if (bin.bits == 32) {
        api.setArchitecture(triton::arch::ARCH_X86);
        ip = triton::arch::ID_REG_EIP;
    } else if (bin.bits == 64) {
        api.setArchitecture(triton::arch::ARCH_X86_64);
        ip = triton::arch::ID_REG_RIP;
    } else {
        fprintf(stderr, "Unsupported bit width for x86: %u bits\n", bin.bits);
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    Binary bin;
    triton::API api;
    triton::arch::registers_e ip;
    std::map<triton::arch::registers_e /*register type*/, uint64_t /*value*/> regs; /** @brief register에대한 구체적인 값*/
    std::map<uint64_t /*address*/, uint8_t /*value*/> mem;                          /** @brief memory에 대한 구체적인 값 */

    if (argc < 6) {
        /*                 argv[1    argv[2]  argv[3]  argv[4]   argv[5] */
        printf("Usage: %s <binary><sym-config><entry><slice-addr><reg>\n", argv[0]);
        return 1;
    }

    std::string fname(argv[1]); /** set file name */
    if (load_binary(fname, &bin, Binary::BIN_TYPE_AUTO) < 0) {
        return 1;
    }

    if (set_triton_arch(bin, api, ip) < 0) { /** 아키텍쳐 정보 설정*/
        return 1;
    }

    api.enableMode(triton::modes::ALIGNED_MEMORY, true);  // 에뮬레이션 수행시 정렬된 메모리 주소로 설정

    if (parse_sym_config(argv[2], &regs, &mem) < 0) {  // memory와 register의 구체적인 값을설정한다.
        return 1;
    }

    for (auto &kv : regs) {
        triton::arch::Register r = api.getRegister(kv.first);
        api.setConcreteRegisterValue(r, kv.second);  // register의 구체적인 값 설정
    }

    for (auto &kv : mem) {
        api.setConcreteMemoryValue(kv.first, kv.second);  // memory에 구체적인 값 설정
    }

    uint64_t pc = strtoul(argv[3], NULL, 0);          // Entry Point
    uint64_t slice_addr = strtoul(argv[4], NULL, 0);  // Slice Address
    Section *sec = bin.get_text_section();

    while (sec->contains(pc)) {  // EP부터 실제 명령어들의 에뮬레이팅
        char mnemonic[32], operands[200];
        int len = disasm_one(sec, pc, mnemonic, operands);  // 명령어 디스어셈블
        if (len <= 0) {
            return 1;
        }

        // 명령어의 Opcode와 주소를 설정
        triton::arch::Instruction insn;
        insn.setOpcode(sec->bytes + (pc - sec->vma) /*offset*/, len);
        insn.setAddress(pc);

        api.processing(insn);  // 실질적인 triton의 명령어 에뮬레이팅 실행

        for (auto &se : insn.symbolicExpressions) {  // 기호적 상태에 주석 추가
            std::string comment = mnemonic;
            comment += " ";
            comment += operands;
            se->setComment(comment);
        }

        if (pc == slice_addr) {  // 찾고자 슬라이스 하고자 했던 명령어의 주소로 도달했다면
            print_slice(api, sec, slice_addr, get_trition_regnum(argv[5]), argv[5]);
            break;
        }
    }

    return 0;
}
