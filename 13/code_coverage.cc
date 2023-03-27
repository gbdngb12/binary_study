#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <map>
#include <string>
#include <triton/api.hpp>
#include <triton/x86Specifications.hpp>
#include <vector>

#include "../inc/loader.h"
#include "disasm_util.h"
#include "triton_util.h"

/**
 * @brief code coverage를 늘리고자 한 주소에 도착한후 taken되지 않은곳으로의 입력 제약 조건을 찾는다.
 * @param api triton api
 * @param sec binary의 section
 * @param branch_addr code coverage를 늘리고자하는 branch의 address
 */
void find_new_input(triton::API &api, Section *sec, uint64_t branch_addr);


/**
 * @brief PC를 다루기위해 triton의 아키텍처 정보를 설정한다.
 * @param bin 바이너리 로더로 로드한 바이너리
 * @param api triton api 참조
 * @param ip PC 레지스터 정보
 * @return 성공 / 실패
 */
int set_triton_arch(Binary &bin, triton::API &api, triton::arch::registers_e &ip);

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
void find_new_input(triton::API &api, Section *sec, uint64_t branch_addr) {
    triton::ast::AstContext &ast = api.getAstContext();                                 /** AST Context 참조*/
    triton::ast::AbstractNode *constraint_list = ast.equal(ast.bvtrue(), ast.bvtrue()); /** 제약 조건 목록 초기화*/

    printf("evaluating branch 0x%jx:\n", branch_addr);

    const std::vector<triton::engines::symbolic::PathConstraint> &path_constraints = api.getPathConstraints();
    /** 지금 까지의 제약 조건 누적 목록을 가져온다*/
    /**
     * @todo 지금 까지의 누적 제약 조건들 중 나머지는 그대로 유지하고 코드 커버리지를 늘리고자하는 목적지의 제약 조건만 반대로 뒤집으면 된다.
     */

    for (auto &pc : path_constraints) {
        if (!pc.isMultipleBranches()) continue;  // 단순 점프는 무시, branch만 검사한다.
        for (auto &branch_constraint : pc.getBranchConstraints()) {
            bool flag = std::get<0>(branch_constraint);  // 현재 branch의 현재 경로가 방문 됐는지 조사한다.
            uint64_t src_addr = std::get<1>(branch_constraint);
            uint64_t dst_addr = std::get<2>(branch_constraint);
            triton::ast::AbstractNode *constraint = std::get<3>(branch_constraint);

            if (src_addr != branch_addr) {                                    // 우리가 찾는곳이 아니라면
                if (flag) {                                                   // 이미 방문 했다면
                    constraint_list = ast.land(constraint_list, constraint);  // 제약조건에 복사
                }
            } else {  // 우리가 찾는곳!
                printf("    0x%jx -> 0x%jx (%staken)\n", src_addr, dst_addr, flag ? "" : "not ");

                if (!flag) {  // taken하지 않았다면 제약 조건을 반대로 뒤집어서 답을 찾는다.
                    printf("    computin new input for 0x%jx -> 0x%jx\n", src_addr, dst_addr);
                    constraint_list = ast.land(constraint_list, constraint);

                    for (auto &kv : api.getModel(constraint_list)) {  // 제약 조건 풀이기 호출
                        printf("    SymVar %u (%s) = 0x%jx\n", kv.first,
                               api.getSymbolicVariableFromId(kv.first)->getComment().c_str(),
                               (uint64_t)kv.second.getValue());
                    }
                }
            }
        }
    }
}

int main(int argc, char *argv[]) {
    Binary bin;
    triton::API api;
    triton::arch::registers_e ip;
    std::map<triton::arch::registers_e, uint64_t> regs; /** @brief register에 대한 실제적 값*/
    std::map<uint64_t, uint8_t> mem;                    /** @brief memory에 대한 실제적 값*/
    std::vector<triton::arch::registers_e> symregs;     /** @brief 기호로 설정할 레지스터 정보*/
    std::vector<uint64_t> symmem;                       /** @briefi 기호로 설정할 메모리 주소 정보*/

    if (argc < 5) {
        printf("Usage: %s <binary> <sym-config> <entry> <branch-addr>\n", argv[0]);
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

    if (parse_sym_config(argv[2], &regs, &mem, &symregs, &symmem) < 0) {  // memory와 register의 구체적인 값 및 기호적 상태 값을설정한다.
        return 1;
    }

    for (auto &kv : regs) {  // 구체적 register 값 설정
        triton::arch::Register r = api.getRegister(kv.first);
        api.setConcreteRegisterValue(r, kv.second);  // register값 구체화
    }

    for (auto regid : symregs) {  // register에 대한 기호화 수행
        triton::arch::Register r = api.getRegister(regid);
        api.convertRegisterToSymbolicVariable(r)->setComment(r.getName());  // Register -> Symbolic Value
    }

    for (auto &kv : mem) {  // 메모리에 대한 구체적 값 설정
        api.setConcreteMemoryValue(kv.first, kv.second);
    }
    for (auto memaddr : symmem) {  // memory에 대한 기호화 수행
        api.convertMemoryToSymbolicVariable(triton::arch::MemoryAccess(memaddr, 1))->setComment(std::to_string(memaddr));
        // memory -> Symbolic Value
    }

    uint64_t pc = strtoul(argv[3], NULL, 0);           // Entry Point
    uint64_t branch_addr = strtoul(argv[4], NULL, 0);  // code coverage를 늘리고자 하는 branch의 주소
    Section *sec = bin.get_text_section();

    while (sec->contains(pc)) {
        char mnemonic[32], operands[200];
        int len = disasm_one(sec, pc, mnemonic, operands);
        if (len <= 0) return 1;

        // 명령어의 OpCode와 Address 설정
        triton::arch::Instruction insn;
        insn.setOpcode(sec->bytes + (pc - sec->vma) /*offset*/, len);
        insn.setAddress(pc);

        api.processing(insn);  // 실질적인 triton의 명령어 에뮬레이팅 실행

        if (pc == branch_addr) {  // code coverage를 늘리고자하는 곳에 도착했다면
            find_new_input(api, sec, branch_addr);
            break;
        }

        pc = (uint64_t)api.getConcreteRegisterValue(api.getRegister(ip));  // update PC
    }
    unload_binary(&bin);
    return 0;
}