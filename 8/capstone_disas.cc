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

    unload_binary(&bin);  // 3. unload Binary

    return 0;  // 4. End Of Program
}

int disasm(Binary *bin, disas::Type disas_type) {
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

    if (disas_type == disas::Type::LINEAR) {
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
        
    }

    cs_free(insns, n);
    cs_close(&dis);

    return 0;
}