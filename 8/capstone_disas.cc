#include "capstone_disas.h"

int main(int argc, char *argv[]) {
    Binary bin;
    std::string fname;

    if (argc < 2) {
        printf("Usage: %s <binary>\n", argv[0]);
        return 1;
    }

    fname.assign(argv[1]);

    if (load_binary(fname, &bin, Binary::BIN_TYPE_AUTO) < 0) {  // 1. load Binary
        return 1;
    }

    if (disasm(&bin, disas::Type::LINEAR) < 0) {  // 2. Linear Disassemble Binary
        return 1;
    }
    // find_gadgets(&bin);

    unload_binary(&bin);  // 3. unload Binary

    return 0;  // 4. End Of Program
}

int disasm(Binary *bin, disas::Type disas_type) {
    if (disas_type == disas::Type::LINEAR) {
        csh dis;        /** @brief 캡스톤 핸들 */
        cs_insn *insns; /** @brief 캡스톤 명령어 버퍼 포인터*/
        Section *text;  /** @brief text Section*/
        size_t n;       /** @brief 읽은 명령어 수*/

        text = bin->get_text_section();
        if (!text) {
            fprintf(stderr, "Nothing to disassemble\n");
            return -1;
        }

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &dis) != CS_ERR_OK) {
            fprintf(stderr, "Failed to open Capstone\n");
            return -1;
        }
        n = cs_disasm(dis, text->bytes, text->size, text->vma, 0 /*가능한 많이 읽기*/, &insns /*여기에 n개 할당*/);
        if (n <= 0) {
            fprintf(stderr, "Disassembly error : %s\n", cs_strerror(cs_errno(dis)));
            return -1;
        }

        for (size_t i = 0; i < n; i++) {
            printf("0x%016jx: ", insns[i].address);
            for (size_t j = 0; j < 16; j++) {
                if (j < insns[i].size)
                    printf("%02x ", insns[i].bytes[j]);
                else
                    printf("   ");
            }
            printf("%-12s %s\n", insns[i].mnemonic, insns[i].op_str);
        }
        cs_free(insns, n);
        cs_close(&dis);
    } else if (disas_type == disas::Type::RECURSIVE) {
        csh dis;
        cs_insn *cs_ins;
        Section *text;
        size_t n;
        const uint8_t *pc;
        uint64_t addr, offset, target;
        std::queue<uint64_t> Q;
        std::map<uint64_t, bool> seen;

        text = bin->get_text_section();  // get textSection
        if (!text) {
            fprintf(stderr, "Nothing to disassemble\n");
            return 0;
        }

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &dis) != CS_ERR_OK) {
            fprintf(stderr, "Failed to open Capstone\n");
            return -1;
        }
        cs_option(dis, CS_OPT_DETAIL, CS_OPT_ON);
        /// (1) CS_OP_DETAIL = CS_OPT_ON //Detail이 ON으로 되어 있어야하고
        /// (2) Engine is not in Skipdata mode (CS_OP_SKIPDATA option set to CS_OPT_ON)

        cs_ins = cs_malloc(dis);  // 명령어를 저장할 버퍼 할당
        if (!cs_ins) {
            fprintf(stderr, "Out of memory\n");
            cs_close(&dis);
            return -1;
        }

        /*
                        Q
            ---------------------------------------------------------------------------
         <-  EntryPoint,  Function Address, conditional branch immediate Address, ...   <-
            ---------------------------------------------------------------------------

        */
        addr = bin->entry;
        if (text->contains(addr)) Q.push(addr);  // 1. EP를 먼저 큐에 넣는다.
        printf("entry point: 0x%016jx\n", addr);

        for (auto &sym : bin->symbols) {
            if (sym.type == Symbol::SYM_TYPE_FUNC && text->contains(sym.addr)) {  // 모든 함수들의 주소를 큐에 넣는다.
                Q.push(sym.addr);
                printf("function symbol: 0x%016jx\n", sym.addr);
            }
        }

        while (!Q.empty()) {  // 모든 EP, 함수, branch를 순회한다.
            addr = Q.front();
            Q.pop();
            if (seen[addr]) {  // default value is zero, 이미 disassemble 했다면
                printf("ignoring addr 0x%016jx (already seen)\n", addr);
                continue;
            }

            offset = addr - text->vma;
            pc = text->bytes + offset;                                     // 현재 읽고 있는 부분
            n = text->size - offset;                                       // 남은 크기
                                                                           /*
                                                                           .text Section
                                                                           text->vma ---> 0x40000   ────┐
                                                                                    ┌──── 0x40001       │
                                                                           offset   │                   │
                                                                                    └────  ...          │
                                                                           addr(init)---> 0x50000       │ size
                                                                                          0x50001       │
                                                                           pc, addr  ---> 0x50002       │
                                                                                          0x50003       │
                                                                                          0x50004       │
                                                                                           ...          │
                                                                                          0x60000   ────┘
                                                                           */
            while (cs_disasm_iter(dis, &pc, &n, &addr, cs_ins)) {          // cs_disasm의 반복 순회용 변형, 한번에 한 개의 명령어만 디스어셈블 & pc 갱신 & 남은크기(n) 갱신,
                if (cs_ins->id == X86_INS_INVALID || cs_ins->size == 0) {  // 읽은 명령어가 invalid 하거나 크기가 0이면 break
                    break;
                }

                seen[cs_ins->address] = true;
                print_ins(cs_ins);  // 현재 명령어 출력

                if (is_cs_cflow_ins(cs_ins)) {                                // branch(call, ret, jump, interrupt(In x86 : syscall int 0x80))인지 확인한다.
                    target = get_cs_ins_immediate_target(cs_ins);             // branch이면 immediate branch에 대해서만 Q에 삽입하기 위해 target 주소를 가져온다.
                    if (target && !seen[target] && text->contains(target)) {  // target이 존재하고, 방문하지 않았고 text Section에 포함 된다면
                        Q.push(target);                                       // 해당 immediate에 대해서도 Q에 삽입하여 디스어셈블 해야함
                        printf("  -> new target: 0x%016jx\n", target);
                    }
                    if (is_cs_unconditional_cflow_ins(cs_ins)) {  // 조건이 없는 branch이면 break
                                                                  //  jmp 0x110100 이라는 식을 만나서 여기 까지 들어왔으면 어차피 밑에부분은 실행되지 않으므로(재귀적
                                                                  //  디스어셈블 방식의 특징) 더이상 읽지 않는다.
                        break;
                    }
                } else if (cs_ins->id == X86_INS_HLT)  // branch가 아니고 halt라면 break
                    break;
                // 아무것도 아니면 그냥 continue
            }
            printf("----------\n");
        }

        cs_free(cs_ins, 1);
        cs_close(&dis);
    }

    return 0;
}

void print_ins(cs_insn *ins) {
    printf("0x%016jx: ", ins->address);
    for (size_t i = 0; i < 16; i++) {
        if (i < ins->size)
            printf("%02x ", ins->bytes[i]);
        else
            printf("   ");  // for Command space
    }
    printf("%-12s %s\n", ins->mnemonic, ins->op_str);
}

bool is_cs_cflow_group(uint8_t g) {
    return (g == CS_GRP_JUMP) || (g == CS_GRP_CALL) || (g == CS_GRP_RET) || (g == CS_GRP_IRET);
    // jump, call, ret, interrupt인지 확인한다.
}

bool is_cs_cflow_ins(cs_insn *ins) {                          // branch(call, ret, jump, interrupt)인지 확인한다.
    for (size_t i = 0; i < ins->detail->groups_count; i++) {  // x86 명령어 세트에 속한 명령어 그룹의 수를 순회
        if (is_cs_cflow_group(ins->detail->groups[i])) {      // 현재 명령어 의 그룹 확인(jump, call, ret interrupt인지)
            return true;
        }
    }
    return false;
}

uint64_t get_cs_ins_immediate_target(cs_insn *ins) {
    cs_x86_op *cs_op;

    for (size_t i = 0; i < ins->detail->groups_count; i++) {
        if (is_cs_cflow_group(ins->detail->groups[i])) {              // 현재 명령어 의 그룹 확인(jump, call, ret interrupt인지)
            for (size_t j = 0; j < ins->detail->x86.op_count; j++) {  // x86 operand의 수
                cs_op = &ins->detail->x86.operands[j];                // cs_op는 opearnd
                if (cs_op->type == X86_OP_IMM) {
                    return cs_op->imm;  // immediate Value
                }
            }
        }
    }
    return 0;
}

bool is_cs_unconditional_cflow_ins(cs_insn *ins) {  // 조건이 없는 branch인지 확인한다.
    switch (ins->id) {
        case X86_INS_JMP:
        case X86_INS_LJMP:
        case X86_INS_RET:
        case X86_INS_RETF:
        case X86_INS_RETFQ:
            return true;
        default:
            return false;
    }
}

int find_gadgets(Binary *bin) {
    csh dis;
    Section *text;
    std::map<std::string, std::vector<uint64_t>> gadgets;

    const uint8_t x86_opc_ret = 0xc3;  // ret Command hex Code

    text = bin->get_text_section();
    if (!text) {
        fprintf(stderr, "Nothing to disassemble\n");
        return 0;
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &dis) != CS_ERR_OK) {
        fprintf(stderr, "Failed to open Capstone\n");
        return -1;
    }
    cs_option(dis, CS_OPT_DETAIL, CS_OPT_ON);

    for (size_t i = 0; i < text->size; i++) {
        if (text->bytes[i] == x86_opc_ret) {                                     // find ret
            if (find_gadgets_at_root(text, text->vma + i, &gadgets, dis) < 0) {  // ret 명령어가 나오면 gadgets 변수에 ret명령어를 root로 하는 5개의 gadget를 저장한다.
                break;
            }
        }
    }

    for (auto &kv : gadgets) {
        printf("%s\t[ ", kv.first.c_str());
        for (auto addr : kv.second) {
            printf("0x%jx ", addr);
        }
        printf("]\n");
    }
    return 0;
}

bool is_cs_ret_ins(cs_insn *ins) {
    switch (ins->id) {
        case X86_INS_RET:
            return true;
        default:
            return false;
    }
}

int find_gadgets_at_root(Section *text, uint64_t root, std::map<std::string, std::vector<uint64_t>> *gadgets, csh dis) {
    size_t n, len;
    const uint8_t *pc;
    uint64_t offset, addr;
    std::string gadget_str;
    cs_insn *cs_ins;

    const size_t max_gadget_len = 5;                                  // instructions 갯수
    const size_t x86_max_ins_bytes = 15;                              // x86 명령어 최대 바이트 수
    const uint64_t root_offset = max_gadget_len * x86_max_ins_bytes;  // 5개 x 15 byte
    cs_ins = cs_malloc(dis);
    if (!cs_ins) {
        fprintf(stderr, "Out of memory\n");
        return -1;
    }

    for (uint64_t a = root - 1; text->contains(a) && a >= root - root_offset; a--) {
        addr = a;                   // vma
        offset = addr - text->vma;  // 현재 까지 읽은 파일 오프셋
        pc = text->bytes + offset;  // 현재 읽는 vma
        n = text->size - offset;    // 남은 파일 오프셋
        len = 0;                    // gadets에 추가한 명령어의 라인의 수
        gadget_str = "";
        while (cs_disasm_iter(dis, &pc, &n, &addr, cs_ins)) {
            if (cs_ins->id == X86_INS_INVALID || cs_ins->size == 0) {  // 유효하지 않은 명령어일 경우 break
                break;
            } else if (cs_ins->address > root) {  // 현재 읽고있는것 보다는 위를 읽어야함
                break;
            } else if (is_cs_cflow_ins(cs_ins) && !is_cs_ret_ins(cs_ins)) {  // ret 명령어가 아닌 제어흐름 명령어발견시 break
                break;
            } else if (++len > max_gadget_len) {  // 범위를 초과할경우 break
                break;
            }

            gadget_str += std::string(cs_ins->mnemonic) + " " + std::string(cs_ins->op_str);
            if (cs_ins->address == root) {
                (*gadgets)[gadget_str].push_back(a);  // 명령어 니모닉에 대한 파일 오프셋 주소
                break;
            }

            gadget_str += "; ";
        }
    }

    cs_free(cs_ins, 1);

    return 0;
}