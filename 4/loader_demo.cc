#include <stdint.h>
#include <stdio.h>

#include <algorithm>
#include <iostream>
#include <string>

#include "../inc/loader.h"

const char *getTypeName(const Symbol::SymbolType &type) {
    if (type == Symbol::SYM_TYPE_FUNC)
        return "FUNC";
    if (type == Symbol::SYM_TYPE_WEAK)
        return "WEAK";
    if (type == Symbol::SYM_TYPE_GLOBAL)
        return "GLOBAL";
    return "";
}

int main(int argc, char *argv[]) {
    size_t i;
    Binary bin;
    Section *sec;
    Symbol *sym;
    std::string fname;

    if (argc < 2) {
        printf("Usage %s <binary>\n", argv[0]);
        return 1;
    }

    fname.assign(argv[1]);

    if (load_binary(fname, &bin, Binary::BIN_TYPE_AUTO) < 0) {
        return 1;
    }

    printf("loaded binary '%s' %s/%s (%u bits) entry@0x%016jx\n",
           bin.filename.c_str(),
           bin.type_str.c_str(), bin.arch_str.c_str(),
           bin.bits, bin.entry);
    for (const auto &sec : bin.sections) {
        printf("    0x%016jx %-8ju %-20s %s\n",
               sec.vma, sec.size, sec.name.c_str(), sec.type == Section::SEC_TYPE_CODE ? "CODE" : "DATA");
    }

    if (bin.symbols.size() > 0) {
        printf("scanned symbol tables\n");
        for (const auto &sym : bin.symbols) {
            printf("    %-40s 0x%016jx %s\n", sym.name.c_str(), sym.addr,
                   getTypeName(sym.type));
        }
    }
    std::string sectionName;
    std::cout << "Input Section Name : ";
    std::cin >> sectionName;

    auto result = std::find_if(bin.sections.begin(), bin.sections.end(), [&sectionName](const Section &s) { return s.name == sectionName; });

    if (result != bin.sections.end()) {
        std::cout << "Section Name : " << (*result).name << std::endl;
        std::cout << "Section size : " << (*result).size << std::endl;
        std::cout << "Section type : " << (*result).type << std::endl;
        std::cout << "Section vma : " << (*result).vma << std::endl;
        // std::cout << "Section Name : "<<(*result).bytes << std::endl;
        for (uint64_t i = 0; i < (*result).size; i++) {
            printf("%x ", (*result).bytes[i]);
        }
    }

    unload_binary(&bin);

    return 0;
}