#include "loader.h"

static bfd *open_bfd(std::string &fname) {
    static int bfd_inited = 0;  // bfd_init()함수를 딱 1번만 호출하기 위함.
    bfd *bfd_h;                 // bfd 라이브러리의 최상위 자료구조, 즉 bfd 파일 타입의 파일 핸들러 포인터

    if (!bfd_inited) {
        bfd_init();
        bfd_inited = 1;
    }

    bfd_h = bfd_openr(fname.c_str(), NULL);  // 두번째 매개변수는 바이너리의 형식을 넘겨줘야한다. NULL이면 자동 판단
    if (!bfd_h) {
        fprintf(stderr, "failed to open binary '%s' (%s)\n", fname.c_str(), bfd_errmsg(bfd_get_error()));
        return NULL;
    }

    if (!bfd_check_format(bfd_h, bfd_object)) {  // 바이너리의 타입을 확인한다. 실행가능한바이너리, 재배치 가능한 Object파일, Shared Library
        fprintf(stderr, "file '%s' does not look like an executable (%s)\n", fname.c_str(), bfd_errmsg(bfd_get_error()));
        return NULL;
    }

    /*
        일부 버전의 bfd_check_format함수는 실행전 '잘못된 형식 오류'를 초기 설정후 함수를 실행하고
        이를 수동으로 해제 해야한다.
    */
    bfd_set_error(bfd_error_no_error);

    if (bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour) {  // msdos, coff, elf등의 알려진 파일 형식을 반환하는 함수
        fprintf(stderr, "unrecognized format for binary '%s' (%s)\n", fname.c_str(), bfd_errmsg(bfd_get_error()));
        return NULL;
    }

    return bfd_h;
}

static int load_symbols_bfd(bfd *bfd_h, Binary *bin) {
    int ret;
    long n, nsyms, i;
    asymbol **bfd_symtab;
    Symbol *sym;

    bfd_symtab = NULL;

    n = bfd_get_symtab_upper_bound(bfd_h);  // static Link symbol 전체 크기
    if (n < 0) {
        fprintf(stderr, "failed to read symtab (%s)\n", bfd_errmsg(bfd_get_error()));
        return -1;
    } else if (n) {
        bfd_symtab = (asymbol **)malloc(n);
        if (!bfd_symtab) {
            fprintf(stderr, "out of memory\n");
            return -1;
        }
    }
    nsyms = bfd_canonicalize_symtab(bfd_h, bfd_symtab);
    if (nsyms < 0) {
        fprintf(stderr, "failed to read symtab (%s)\n", bfd_errmsg(bfd_get_error()));
        return -1;
    }

    for (i = 0; i < nsyms; i++) {
        if (bfd_symtab[i]->flags & BSF_FUNCTION) {  // The symbol type is only a FUNC Type
            bin->symbols.push_back(Symbol());
            sym = &bin->symbols.back();
            sym->type = Symbol::SYM_TYPE_FUNC;
            sym->name = std::string(bfd_symtab[i]->name);
            sym->addr = bfd_asymbol_value(bfd_symtab[i]);
        } else if (bfd_symtab[i]->flags & BSF_WEAK) {
            bin->symbols.push_back(Symbol());
            sym = &bin->symbols.back();
            sym->type = Symbol::SYM_TYPE_WEAK;
            sym->name = std::string(bfd_symtab[i]->name);
            sym->addr = bfd_asymbol_value(bfd_symtab[i]);
        } else if (bfd_symtab[i]->flags & BSF_GLOBAL) {
            bin->symbols.push_back(Symbol());
            sym = &bin->symbols.back();
            sym->type = Symbol::SYM_TYPE_GLOBAL;
            sym->name = std::string(bfd_symtab[i]->name);
            sym->addr = bfd_asymbol_value(bfd_symtab[i]);
        }
    }

    if (bfd_symtab)
        free(bfd_symtab);

    return 0;
}

static int load_dynsym_bfd(bfd *bfd_h, Binary *bin) {
    int ret;
    long n, nsyms, i;
    asymbol **bfd_dynsym;
    Symbol *sym;

    bfd_dynsym = NULL;

    n = bfd_get_dynamic_symtab_upper_bound(bfd_h);  // dynamic Link symbol 전체 크기
    if (n < 0) {
        fprintf(stderr, "failed to read symtab (%s)\n", bfd_errmsg(bfd_get_error()));
        return -1;
    } else if (n) {
        bfd_dynsym = (asymbol **)malloc(n);
        if (!bfd_dynsym) {
            fprintf(stderr, "out of memory\n");
            return -1;
        }
    }
    nsyms = bfd_canonicalize_dynamic_symtab(bfd_h, bfd_dynsym);
    if (nsyms < 0) {
        fprintf(stderr, "failed to read symtab (%s)\n", bfd_errmsg(bfd_get_error()));
        return -1;
    }

    for (i = 0; i < nsyms; i++) {
        if (bfd_dynsym[i]->flags & BSF_FUNCTION) {  // The symbol type is only a FUNC Type
            bin->symbols.push_back(Symbol());
            sym = &bin->symbols.back();
            sym->type = Symbol::SYM_TYPE_FUNC;
            sym->name = std::string(bfd_dynsym[i]->name);
            sym->addr = bfd_asymbol_value(bfd_dynsym[i]);
        } else if (bfd_dynsym[i]->flags & BSF_WEAK) {
            bin->symbols.push_back(Symbol());
            sym = &bin->symbols.back();
            sym->type = Symbol::SYM_TYPE_WEAK;
            sym->name = std::string(bfd_dynsym[i]->name);
            sym->addr = bfd_asymbol_value(bfd_dynsym[i]);
        } else if (bfd_dynsym[i]->flags & BSF_GLOBAL) {
            bin->symbols.push_back(Symbol());
            sym = &bin->symbols.back();
            sym->type = Symbol::SYM_TYPE_GLOBAL;
            sym->name = std::string(bfd_dynsym[i]->name);
            sym->addr = bfd_asymbol_value(bfd_dynsym[i]);
        }
        // BSF_NO_FLAGS
        // BSF_LOCAL
        // BSF_DEBUGGING
        // BSF_KEEP
        // BSF_ELF_COMMON
        // BSF_SECTION_SYM
        // BSF_OLD_COMMON
        // BSF_NOT_AT_END
        // BSF_CONSTRUCTOR
        // BSF_WARNING
        // BSF_INDIRECT
        // BSF_FILE
        // BSF_DYNAMIC
        // BSF_OBJECT
        // BSF_DEBUGGING_RELOC
        // BSF_THREAD_LOCAL
        // BSF_RELC
        // BSF_SRELC
        // BSF_SYNTHETIC
        // BSF_GNU_INDIRECT_FUN
        // BSF_GNU_UNIQUE
        // BSF_SECTION_SYM_USED
    }

    if (bfd_dynsym)
        free(bfd_dynsym);

    return 0;
}

static int load_sections_bfd(bfd *bfd_h, Binary *bin) {
    unsigned int bfd_flags;
    uint64_t vma, size;
    const char *secname;
    asection *bfd_sec;
    Section *sec;
    Section::SectionType sectype;

    for (bfd_sec = bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next) {
        bfd_flags = bfd_sec->flags;  // bfd_flags = bfd_get_section_flags(bfd_h, bfd_sec);

        sectype = Section::SEC_TYPE_NONE;
        if (bfd_flags & SEC_CODE) {
            sectype = Section::SEC_TYPE_CODE;
        } else if (bfd_flags & SEC_DATA) {
            sectype = Section::SEC_TYPE_DATA;
        } else {
            continue;
        }

        vma = bfd_section_vma(bfd_sec);
        size = bfd_section_size(bfd_sec);
        secname = bfd_section_name(bfd_sec);
        if (!secname)
            secname = "<unnamed>";

        bin->sections.push_back(Section());
        sec = &bin->sections.back();

        sec->binary = bin;
        sec->name = std::string(secname);
        sec->type = sectype;
        sec->vma = vma;
        sec->size = size;
        sec->bytes = (uint8_t *)malloc(size);
        if (!sec->bytes) {
            fprintf(stderr, "out of memory\n");
            return -1;
        }

        if (!bfd_get_section_contents(bfd_h, bfd_sec, sec->bytes, 0, size)) {
            fprintf(stderr, "failed to read section '%s' (%s)\n", secname, bfd_errmsg(bfd_get_error()));
            return -1;
        }
    }
    return 0;
}

static int load_binary_bfd(std::string &fname, Binary *bin, Binary::BinaryType type) {
    bfd *bfd_h;
    const bfd_arch_info_type *bfd_info;

    bfd_h = NULL;
    bfd_h = open_bfd(fname);
    if (!bfd_h)
        return -1;

    bin->filename = std::string(fname);
    bin->entry = bfd_get_start_address(bfd_h);  // Get entry Point Address

    bin->type_str = std::string(bfd_h->xvec->name);  // bfd_target 구조체 => 현재 바이너리 타입에 해당하는 구조체
    switch (bfd_h->xvec->flavour) {
        case bfd_target_elf_flavour:
            bin->type = Binary::BIN_TYPE_ELF;
            break;
        case bfd_target_coff_flavour:
            bin->type = Binary::BIN_TYPE_PE;
            break;
        case bfd_target_unknown_flavour:
            [[fallthrough]];
        default:
            fprintf(stderr, "unsupported binary type (%s)\n", bfd_h->xvec->name);
            return -1;
            break;
    }

    bfd_info = bfd_get_arch_info(bfd_h);
    bin->arch_str = std::string(bfd_info->printable_name);

    switch (bfd_info->mach) {
        case bfd_mach_i386_i386:
            bin->arch = Binary::ARCH_X86;
            bin->bits = 32;
            break;
        case bfd_mach_x86_64:
            bin->arch = Binary::ARCH_X86;
            bin->bits = 64;
            break;
        default:
            fprintf(stderr, "unsupported architecture (%s)\n", bfd_info->printable_name);
            return -1;
            break;
    }

    load_symbols_bfd(bfd_h, bin);  // 복잡한 과정을 수반하므로 별도의 함수 load_symbol_bfd를 만들어 호출
    load_dynsym_bfd(bfd_h, bin);

    if (load_sections_bfd(bfd_h, bin) < 0)
        return -1;

    if (bfd_h)
        bfd_close(bfd_h);
    return 0;
}

int load_binary(std::string &fname, Binary *bin, Binary::BinaryType type) {
    return load_binary_bfd(fname, bin, type);  // 복잡한 과정을 수반하므로 별도의 함수 load_binary_bfd를 만들어 호출
}

void unload_binary(Binary *bin) {
    size_t i;
    for (auto &sec : bin->sections) {
        if (sec.bytes) {
            free(sec.bytes);  // 실제 Section의 크기만큼 할당 받은 메모리. 즉, 실제 Section의 내용
        }
    }
}