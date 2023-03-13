[Read to Notion](https://bolder-cloud-3a9.notion.site/4-LIBBFD-fab5467dc35143b09bdbf012e3913cb4)
# 4장. LIBBFD를 이용한 바이너리 로더 제작

```
**libbfd를 이용한 바이너리 로더 제작**
├── **libbfd란 무엇인가?**
├── **바이너리 로더 인터페이스**
│   ├── Binary class
│   ├── Section class
│   └── Symbol class
├── **바이너리 로더 구현**
│   ├── libbfd 초기화하고 바이너리 열기
│   ├── 바이너리 기본 정보 분석하기
│   ├── symbol 정보 불러오기
│   └── section 정보 불러오기
├── **테스트 코드 및 결과**
└── **연습 문제**
    ├── 섹션 내용 덤프하기
    ├── weak 심벌 오버라이드하기
    └── 데이터 심벌 출력하기
```

- **libbfd란 무엇인가?**
    
    libbfd는 bfd Library의 줄임말이고 bfd는 Binary File Descriptor(바이너리 파일 디스크립터)이다.
    
    ```bash
    $ sudo apt install binutils-dev
    ```
    
    ```c
    #include <bfd.h>
    ```
    
    ```bash
    $ g++ -lstdc++ -std=c++17 input.cc -o input.out **-lbfd**
    ```
    
- **바이너리 로더 인터페이스**
    - **Binary class**
        
        ```cpp
        class Binary {
           public:
            /**
             * @brief Binary Type(ELF/PE/AUTO)
            */
            enum BinaryType {
                BIN_TYPE_AUTO = 0, /** @brief AUTO 자동으로 ELF, PE등을 판별한다.*/
                BIN_TYPE_ELF = 1, /** @brief ELF 파일이다. */
                BIN_TYPE_PE = 2 /** @brief PE 파일이다. */
            };
            /**
             * @brief Binary파일의 아키텍쳐 정보
            */
            enum BinaryArch {
                ARCH_NONE = 0, /** @brief 현재 로더 라이브러리는 x86외에는 지원하지 않는다.*/
                ARCH_X86 = 1 /** @brief x86*/
            };
        
            Binary() : type(BIN_TYPE_AUTO), arch(ARCH_NONE), bits(0), entry(0) {}
        
            /**
             * @brief .text section의 정보를 가져온다.
             * @return .text section Section 클래스의 pointer
            */
            Section *get_text_section() {
                for (auto &s : sections)
                    if (s.name == ".text")
                        return &s;
                return NULL;
            }
        
            /**
             * @brief Binary 파일의 이름(절대경로/상대경로)
            */
            std::string filename;
            /**
             * @brief 바이너리 파일의 타입 ELF/PE
            */
            BinaryType type;
            /**
             * @brief 바이너리 파일타입의 string
            */
            std::string type_str;
            /**
             * @brief 바이너리 파일의 아키텍쳐 정보
            */
            BinaryArch arch;
            /**
             * @brief 바이너리 파일의 아키텍쳐 string
            */
            std::string arch_str;
            /**
             * @brief 바이너리 파일의 비트 64비트/32비트
            */
            unsigned bits;
            /**
             * @brief 바이너리 파일의 Entry Point
            */
            uint64_t entry;
            /**
             * @brief 바이너리 파일의 Section 정보들
            */
            std::vector<Section> sections;
            /**
             * @brief 바이너리 파일의 Symbol 정보들
            */
            std::vector<Symbol> symbols;
        };
        ```
        
    - **Section class**
        
        ```cpp
        class Section {
           public:
            /**
             * @brief Section의 Type
            */
            enum SectionType {
                SEC_TYPE_NONE = 0, /** @brief */
                SEC_TYPE_CODE = 1, /** @brief Code Section*/
                SEC_TYPE_DATA = 2 /** @brief Data Section*/
            };
        
            Section() : binary(NULL), type(SEC_TYPE_NONE), vma(0), size(0), bytes(NULL) {}
        
            /**
             * @brief 현재 Section에 입력한 주소에 해당하는 코드/데이터가 존재하는지 알아낸다.
             * @param addr 코드/데이터가 속한 가상 주소 값
             * @return 
            */
            bool contains(uint64_t addr) {
                return (addr >= vma) && (addr - vma < size);
            }
        
            /**
             * @brief 현재 Section을 이루고있는 Binary 클래스 역참조
             */
            Binary *binary;
            /**
             * @brief Section의 이름
             */
            std::string name;
            /**
             * @brief Section의 Type
             */
            SectionType type;
            /**
             * @brief Start Virtual Address of Section at execution
             * */
            uint64_t vma;
            /**
             * @brief Section의 크기
             */
            uint64_t size;
            /**
             * @brief Section의 실제 내용 bytes
             */
            uint8_t *bytes;
        };
        ```
        
    - **Symbol class**
        
        ```cpp
        class Symbol {
           public:
            /**
             * @brief Symbol 정보
            */
            enum SymbolType {
                SYM_TYPE_UKN = 0, /** @brief */
                SYM_TYPE_FUNC = 1, /** @brief 함수 이름 심벌 정보*/
                SYM_TYPE_WEAK = 2, /** @brief Weak Type은 같은 이름의 GLOBAL Type이 있으면 GLOBAL Symbol로 override된다.*/
                SYM_TYPE_GLOBAL = 3 /** @brief GLOBAL Symbol Type*/
            };
        
            Symbol() : type(SYM_TYPE_UKN), name(), addr(0) {}
            /**
             * @brief Symbol Type
            */
            SymbolType type;
            /**
             * @brief Symbol의 string
            */
            std::string name;
            /**
             * @brief symbol이 존재하는 주소
            */
            uint64_t addr;
        };
        ```
        
- **바이너리 로더 구현**
    - **libbfd 초기화하고 바이너리 열기**
        
        ```cpp
        /**
         * @brief bfd 라이브러리를 이용해 바이너리 파일을 여는 일련의 과정을 수행한다.
         * @param fname 바이너리 파일의 상대/절대 경로
         * @return 성공 : bfd handler / 실패 NULL
        */
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
        /**
         * @brief Binary 클래스의 동적 정보를 모두 해제한다.
         * @param bin 바이너리 클래스 포인터
        */
        void unload_binary(Binary *bin) {
            size_t i;
            for (auto &sec : bin->sections) {
                if (sec.bytes) {
                    free(sec.bytes);  // 실제 Section의 크기만큼 할당 받은 메모리. 즉, 실제 Section의 내용
                }
            }
        }
        ```
        
    - **바이너리 기본 정보 분석하기**
        
        ```cpp
        /**
         * @brief 바이너리파일을 Binary 클래스에 로드한다.
         * @param fname 바이너리 파일 상대/절대 경로
         * @param bin 바이너리 클래스 포인터
         * @param type 바이너리 타입
         * @return -1 : 오류 / 0 성공
        */
        int load_binary(std::string &fname, Binary *bin, Binary::BinaryType type) {
            return load_binary_bfd(fname, bin, type);  // 복잡한 과정을 수반하므로 별도의 함수 load_binary_bfd를 만들어 호출
        }
        /**
         * @brief Binary의 모든 section들을 로드한다. 
         * @param bfd_h bfd handler pointer
         * @param bin 바이너리 클래스 포인터
         * @return -1 : 오류 / 0 성공
        */
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
        ```
        
    - **symbol 정보 불러오기**
        
        ```cpp
        /**
         * @brief Binary의 모든 동적 심벌을 로드한다.
         * @param bfd_h bfd handler pointer
         * @param bin 바이너리 클래스 포인터
         * @return -1 : 오류 / 0 성공
        */
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
        /**
         * @brief  바이너리 파일의 정적 심벌을 모두 로드한다.
         * @param bfd_h bfd handler pointer
         * @param bin Binary 클래스 포인터
         * @return -1 : 오류 / 0 성공
        */
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
        ```
        
    - **section 정보 불러오기**
        
        ```cpp
        /**
         * @brief Binary의 모든 section들을 로드한다. 
         * @param bfd_h bfd handler pointer
         * @param bin 바이너리 클래스 포인터
         * @return -1 : 오류 / 0 성공
        */
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
        ```
        
- **테스트 코드 및 결과**
    
    ```cpp
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
    **$ ./run_loader_demo.sh /home/dong/Downloads/binary_study/4/ls**
    loaded binary '/home/dong/Downloads/binary_study/4/ls' elf64-x86-64/i386:x86-64 (64 bits) entry@0x00000000004049a0
        0x0000000000400238 28       .interp              DATA
        0x0000000000400254 32       .note.ABI-tag        DATA
        0x0000000000400274 36       .note.gnu.build-id   DATA
        0x0000000000400298 192      .gnu.hash            DATA
        0x0000000000400358 3288     .dynsym              DATA
        0x0000000000401030 1500     .dynstr              DATA
        0x000000000040160c 274      .gnu.version         DATA
        0x0000000000401720 112      .gnu.version_r       DATA
        0x0000000000401790 168      .rela.dyn            DATA
        0x0000000000401838 2688     .rela.plt            DATA
        0x00000000004022b8 26       .init                CODE
        0x00000000004022e0 1808     .plt                 CODE
        0x00000000004029f0 8        .plt.got             CODE
        0x0000000000402a00 70233    .text                CODE
        0x0000000000413c5c 9        .fini                CODE
        0x0000000000413c80 26996    .rodata              DATA
        0x000000000041a5f4 2052     .eh_frame_hdr        DATA
        0x000000000041adf8 11372    .eh_frame            DATA
        0x000000000061de00 8        .init_array          DATA
        0x000000000061de08 8        .fini_array          DATA
        0x000000000061de10 8        .jcr                 DATA
        0x000000000061de18 480      .dynamic             DATA
        0x000000000061dff8 8        .got                 DATA
        0x000000000061e000 920      .got.plt             DATA
        0x000000000061e3a0 608      .data                DATA
    scanned symbol tables
        __ctype_toupper_loc                      0x0000000000000000 FUNC
        __uflow                                  0x0000000000000000 FUNC
        getenv                                   0x0000000000000000 FUNC
        sigprocmask                              0x0000000000000000 FUNC
        raise                                    0x0000000000000000 FUNC
        localtime                                0x0000000000000000 FUNC
        __mempcpy_chk                            0x0000000000000000 FUNC
        abort                                    0x0000000000000000 FUNC
        __errno_location                         0x0000000000000000 FUNC
        strncmp                                  0x0000000000000000 FUNC
        _ITM_deregisterTMCloneTable              0x0000000000000000 WEAK
        _exit                                    0x0000000000000000 FUNC
        strcpy                                   0x0000000000000000 FUNC
        __fpending                               0x0000000000000000 FUNC
        isatty                                   0x0000000000000000 FUNC
        sigaction                                0x0000000000000000 FUNC
        iswcntrl                                 0x0000000000000000 FUNC
        wcswidth                                 0x0000000000000000 FUNC
        localeconv                               0x0000000000000000 FUNC
        mbstowcs                                 0x0000000000000000 FUNC
        readlink                                 0x0000000000000000 FUNC
        clock_gettime                            0x0000000000000000 FUNC
        setenv                                   0x0000000000000000 FUNC
        textdomain                               0x0000000000000000 FUNC
        fclose                                   0x0000000000000000 FUNC
        opendir                                  0x0000000000000000 FUNC
        getpwuid                                 0x0000000000000000 FUNC
        bindtextdomain                           0x0000000000000000 FUNC
        stpcpy                                   0x0000000000000000 FUNC
        dcgettext                                0x0000000000000000 FUNC
        __ctype_get_mb_cur_max                   0x0000000000000000 FUNC
        strlen                                   0x0000000000000000 FUNC
        __lxstat                                 0x0000000000000000 FUNC
        __stack_chk_fail                         0x0000000000000000 FUNC
        getopt_long                              0x0000000000000000 FUNC
        mbrtowc                                  0x0000000000000000 FUNC
        strchr                                   0x0000000000000000 FUNC
        getgrgid                                 0x0000000000000000 FUNC
        __overflow                               0x0000000000000000 FUNC
        strrchr                                  0x0000000000000000 FUNC
        fgetfilecon                              0x0000000000000000 FUNC
        gmtime_r                                 0x0000000000000000 FUNC
        lseek                                    0x0000000000000000 FUNC
        gettimeofday                             0x0000000000000000 FUNC
        __assert_fail                            0x0000000000000000 FUNC
        __strtoul_internal                       0x0000000000000000 FUNC
        fnmatch                                  0x0000000000000000 FUNC
        memset                                   0x0000000000000000 FUNC
        fscanf                                   0x0000000000000000 FUNC
        ioctl                                    0x0000000000000000 FUNC
        close                                    0x0000000000000000 FUNC
        closedir                                 0x0000000000000000 FUNC
        __libc_start_main                        0x0000000000000000 FUNC
        memcmp                                   0x0000000000000000 FUNC
        _setjmp                                  0x0000000000000000 FUNC
        fputs_unlocked                           0x0000000000000000 FUNC
        calloc                                   0x0000000000000000 FUNC
        lgetfilecon                              0x0000000000000000 FUNC
        strcmp                                   0x0000000000000000 FUNC
        signal                                   0x0000000000000000 FUNC
        dirfd                                    0x0000000000000000 FUNC
        getpwnam                                 0x0000000000000000 FUNC
        __memcpy_chk                             0x0000000000000000 FUNC
        sigemptyset                              0x0000000000000000 FUNC
        __gmon_start__                           0x0000000000000000 WEAK
        memcpy                                   0x0000000000000000 FUNC
        getgrnam                                 0x0000000000000000 FUNC
        getfilecon                               0x0000000000000000 FUNC
        tzset                                    0x0000000000000000 FUNC
        fileno                                   0x0000000000000000 FUNC
        tcgetpgrp                                0x0000000000000000 FUNC
        __xstat                                  0x0000000000000000 FUNC
        readdir                                  0x0000000000000000 FUNC
        wcwidth                                  0x0000000000000000 FUNC
        fflush                                   0x0000000000000000 FUNC
        nl_langinfo                              0x0000000000000000 FUNC
        ungetc                                   0x0000000000000000 FUNC
        __fxstat                                 0x0000000000000000 FUNC
        strcoll                                  0x0000000000000000 FUNC
        __freading                               0x0000000000000000 FUNC
        fwrite_unlocked                          0x0000000000000000 FUNC
        realloc                                  0x0000000000000000 FUNC
        stpncpy                                  0x0000000000000000 FUNC
        fdopen                                   0x0000000000000000 FUNC
        setlocale                                0x0000000000000000 FUNC
        __printf_chk                             0x0000000000000000 FUNC
        timegm                                   0x0000000000000000 FUNC
        strftime                                 0x0000000000000000 FUNC
        mempcpy                                  0x0000000000000000 FUNC
        memmove                                  0x0000000000000000 FUNC
        error                                    0x0000000000000000 FUNC
        open                                     0x0000000000000000 FUNC
        fseeko                                   0x0000000000000000 FUNC
        _Jv_RegisterClasses                      0x0000000000000000 WEAK
        unsetenv                                 0x0000000000000000 FUNC
        strtoul                                  0x0000000000000000 FUNC
        __cxa_atexit                             0x0000000000000000 FUNC
        wcstombs                                 0x0000000000000000 FUNC
        getxattr                                 0x0000000000000000 FUNC
        freecon                                  0x0000000000000000 FUNC
        sigismember                              0x0000000000000000 FUNC
        exit                                     0x0000000000000000 FUNC
        fwrite                                   0x0000000000000000 FUNC
        __fprintf_chk                            0x0000000000000000 FUNC
        _ITM_registerTMCloneTable                0x0000000000000000 WEAK
        fflush_unlocked                          0x0000000000000000 FUNC
        mbsinit                                  0x0000000000000000 FUNC
        iswprint                                 0x0000000000000000 FUNC
        sigaddset                                0x0000000000000000 FUNC
        strstr                                   0x0000000000000000 FUNC
        __ctype_tolower_loc                      0x0000000000000000 FUNC
        __ctype_b_loc                            0x0000000000000000 FUNC
        __sprintf_chk                            0x0000000000000000 FUNC
        __progname                               0x000000000061e600 GLOBAL
        _fini                                    0x0000000000413c5c FUNC
        optind                                   0x000000000061e610 GLOBAL
        _init                                    0x00000000004022b8 FUNC
        free                                     0x0000000000402340 FUNC
        program_invocation_name                  0x000000000061e620 WEAK
        __bss_start                              0x000000000061e600 GLOBAL
        _end                                     0x000000000061f368 GLOBAL
        __progname_full                          0x000000000061e620 GLOBAL
        _obstack_memory_used                     0x0000000000412930 FUNC
        obstack_alloc_failed_handler             0x000000000061e5f8 GLOBAL
        _obstack_begin                           0x0000000000412750 FUNC
        _edata                                   0x000000000061e600 GLOBAL
        stderr                                   0x000000000061e640 GLOBAL
        _obstack_free                            0x00000000004128c0 FUNC
        program_invocation_short_name            0x000000000061e600 WEAK
        localtime_r                              0x00000000004023a0 FUNC
        _obstack_allocated_p                     0x0000000000412890 FUNC
        optarg                                   0x000000000061e618 GLOBAL
        _obstack_begin_1                         0x0000000000412770 FUNC
        _obstack_newchunk                        0x0000000000412790 FUNC
        malloc                                   0x0000000000402790 FUNC
        stdout                                   0x000000000061e608 GLOBAL
    Input Section Name : .interp
    Section Name : .interp
    Section size : 28
    Section type : 2
    Section vma : 4194872
    2f 6c 69 62 36 34 2f 6c 64 2d 6c 69 6e 75 78 2d 78 38 36 2d 36 34 2e 73 6f 2e 32 0
    ```
    

- **바이너리 로더의 인터페이스 UML 다이어그램**
    
    ```cpp
    #include <stdint.h>
    
    #include <string>
    #include <vector>
    
    class Binary;
    class Section;
    class Symbol;
    
    class Symbol {
       public:
        enum SymbolType {
            SYM_TYPE_UKN = 0,
            SYM_TYPE_FUNC = 1,
            SYM_TYPE_WEAK = 2,
            SYM_TYPE_GLOBAL = 3
        };
    
        Symbol() : type(SYM_TYPE_UKN), name(), addr(0) {}
    
        SymbolType type;
        std::string name;
        uint64_t addr;
    };
    
    class Section {
       public:
        enum SectionType {
            SEC_TYPE_NONE = 0,
            SEC_TYPE_CODE = 1,
            SEC_TYPE_DATA = 2
        };
    
        Section() : binary(NULL), type(SEC_TYPE_NONE), vma(0), size(0), bytes(NULL) {}
    
        bool contains(uint64_t addr) {
            return (addr >= vma) && (addr - vma < size);
        }
    
        Binary *binary;
        std::string name;
        SectionType type;
        uint64_t vma; /* Start Virtual Address of Section at execution*/
        uint64_t size;
        uint8_t *bytes; /*Section의 실제 내용 bytes*/
    };
    
    class Binary {
       public:
        enum BinaryType {
            BIN_TYPE_AUTO = 0,
            BIN_TYPE_ELF = 1,
            BIN_TYPE_PE = 2
        };
        enum BinaryArch {
            ARCH_NONE = 0,
            ARCH_X86 = 1
        };
    
        Binary() : type(BIN_TYPE_AUTO), arch(ARCH_NONE), bits(0), entry(0) {}
    
        Section *get_text_section() {
            for (auto &s : sections)
                if (s.name == ".text")
                    return &s;
            return NULL;
        }
    
        std::string filename;
        BinaryType type;
        std::string type_str;
        BinaryArch arch;
        std::string arch_str;
        unsigned bits;
        uint64_t entry;
        std::vector<Section> sections;
        std::vector<Symbol> symbols;
    };
    ```
    
    ![Untitled](4%E1%84%8C%E1%85%A1%E1%86%BC%20LIBBFD%E1%84%85%E1%85%B3%E1%86%AF%20%E1%84%8B%E1%85%B5%E1%84%8B%E1%85%AD%E1%86%BC%E1%84%92%E1%85%A1%E1%86%AB%20%E1%84%87%E1%85%A1%E1%84%8B%E1%85%B5%E1%84%82%E1%85%A5%E1%84%85%E1%85%B5%20%E1%84%85%E1%85%A9%E1%84%83%E1%85%A5%20%E1%84%8C%E1%85%A6%E1%84%8C%E1%85%A1%E1%86%A8%20fab5467dc35143b09bdbf012e3913cb4/Untitled.png)
    
- 바이너리를 로드하는 **핵심 함수**
    
    ```cpp
    int load_binary(std::string &fname, Binary *bin, Binary::BinaryType type);
    void unload_binary(Binary *bin);
    ```
    
    바이너리를 성공적으로 로드 했다면 0 반환 & Binary 포인터 설정
    
    ```cpp
    int load_binary(std::string &fname, Binary *bin, Binary::BinaryType type) {
        return load_binary_bfd(fname, bin, type);  
    		//복잡한 과정을 수반하므로 별도의 함수 load_binary_bfd를 만들어 호출
    }
    
    void unload_binary(Binary *bin) {
        size_t i;
        for (auto &sec : bin->sections) {
            if (sec.bytes) {
                free(sec.bytes);  
    		//실제 Section의 크기만큼 할당 받은 메모리. 즉, 실제 Section의 내용 포인터 free
            }
        }
    }
    ```
    
- 바이너리를 로드하는 **핵심 함수 구현**
    
    바이너리를 로드하는 과정
    
    - **바이너리 파일을 연다.**
        
        ```cpp
        static bfd *open_bfd(std::string &fname) {
            static int bfd_inited = 0;  
        		// bfd_init()함수를 딱 1번만 호출하기 위함.
            bfd *bfd_h;// bfd 라이브러리의 최상위 자료구조, 즉 bfd 파일 타입의 파일 핸들러 포인터
        		//모든 바이너리의 정보가 담겨있음
        
            if (!bfd_inited) {
                bfd_init();// 한번만 호출하면 됨
                bfd_inited = 1;
            }
        
            bfd_h = bfd_openr(fname.c_str(), NULL);  
        		//두번째 매개변수는 바이너리의 형식을 넘겨줘야한다. NULL이면 자동 판단(By 라이브러리)
            if (!bfd_h) {
                fprintf(stderr, "failed to open binary '%s' (%s)\n", fname.c_str(), bfd_errmsg(bfd_get_error()));
                return NULL;
            }
        
        		// 바이너리의 타입을 확인한다. 실행가능한바이너리, 재배치 가능한 Object파일, 
        		// Shared Library
            if (!bfd_check_format(bfd_h, bfd_object)) {  
                fprintf(stderr, "file '%s' does not look like an executable (%s)\n", fname.c_str(), bfd_errmsg(bfd_get_error()));
                return NULL;
            }
        
            /*
                일부 버전의 bfd_check_format함수는 실행전 '잘못된 형식 오류'를 초기 설정후 
        				함수를 실행하고 이를 수동으로 해제 해야한다.
            */
            bfd_set_error(bfd_error_no_error);
        
        		// msdos, coff(pe), elf등의 알려진 파일 형식을 반환하는 함수
            if (bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour) { 
                fprintf(stderr, "unrecognized format for binary '%s' (%s)\n", fname.c_str(), bfd_errmsg(bfd_get_error()));
                return NULL;
            }
        
            return bfd_h; //모든 바이너리의 정보가 담겨있다.
        }
        ```
        
    - **각종 바이너리 구조의 값**들을 **매핑**한다.
        
        ```cpp
        static int load_binary_bfd(std::string &fname, Binary *bin, Binary::BinaryType type) {
            bfd *bfd_h;
            const bfd_arch_info_type *bfd_info;
        
            bfd_h = NULL;
            bfd_h = open_bfd(fname);//1. 바이너리 파일을 연다.
            if (!bfd_h)
                return -1;
        
        		//사용자가 넘긴 Binary객체의 값 설정
            bin->filename = std::string(fname);
            bin->entry = bfd_get_start_address(bfd_h);  // Get entry Point Address
        
        		// bfd_target 구조체(bfd_h->xvec) => 현재 바이너리의 형식정보 구조체
            bin->type_str = std::string(bfd_h->xvec->name); 
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
        
        		//bfdlib의 아키텍쳐 정보 구조체 가져오는 함수
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
        ```
        
    - **symbol 정보를 매핑**한다.
        
        ```cpp
        static int load_binary_bfd(std::string &fname, Binary *bin, 
        											Binary::BinaryType type) {		
        					....
        // 복잡한 과정을 수반하므로 별도의 함수 load_symbol_bfd를 만들어 호출
        		load_symbols_bfd(bfd_h, bin);
            load_dynsym_bfd(bfd_h, bin);
        
            if (load_sections_bfd(bfd_h, bin) < 0)
                return -1;
        
            if (bfd_h)
                bfd_close(bfd_h);
            return 0;
        }
        ```
        
        ```cpp
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
        				//symbol table의 크기만큼 메모리 동적 할당
                bfd_symtab = (asymbol **)malloc(n);
                if (!bfd_symtab) {
                    fprintf(stderr, "out of memory\n");
                    return -1;
                }
            }
        		//bfd의 symboltable을 bfd_sym에 정규화
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
                } else if(bfd_symtab[i]->flags & BSF_WEAK) {
                    bin->symbols.push_back(Symbol());
                    sym = &bin->symbols.back();
                    sym->type = Symbol::SYM_TYPE_WEAK;
                    sym->name = std::string(bfd_symtab[i]->name);
                    sym->addr = bfd_asymbol_value(bfd_symtab[i]);
                } else if(bfd_symtab[i]->flags & BSF_GLOBAL) {
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
        ```
        
        ```cpp
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
                } else if(bfd_dynsym[i]->flags & BSF_WEAK) {
                    bin->symbols.push_back(Symbol());
                    sym = &bin->symbols.back();
                    sym->type = Symbol::SYM_TYPE_WEAK;
                    sym->name = std::string(bfd_dynsym[i]->name);
                    sym->addr = bfd_asymbol_value(bfd_dynsym[i]);
                } else if(bfd_dynsym[i]->flags & BSF_GLOBAL) {
                    bin->symbols.push_back(Symbol());
                    sym = &bin->symbols.back();
                    sym->type = Symbol::SYM_TYPE_GLOBAL;
                    sym->name = std::string(bfd_dynsym[i]->name);
                    sym->addr = bfd_asymbol_value(bfd_dynsym[i]);
                }
                //BSF_NO_FLAGS
                //BSF_LOCAL
                //BSF_DEBUGGING
                //BSF_KEEP
                //BSF_ELF_COMMON
                //BSF_SECTION_SYM
                //BSF_OLD_COMMON      
                //BSF_NOT_AT_END      
                //BSF_CONSTRUCTOR     
                //BSF_WARNING         
                //BSF_INDIRECT        
                //BSF_FILE            
                //BSF_DYNAMIC         
                //BSF_OBJECT          
                //BSF_DEBUGGING_RELOC 
                //BSF_THREAD_LOCAL    
                //BSF_RELC            
                //BSF_SRELC           
                //BSF_SYNTHETIC       
                //BSF_GNU_INDIRECT_FUN
                //BSF_GNU_UNIQUE      
                //BSF_SECTION_SYM_USED
            }
        
            if (bfd_dynsym)
                free(bfd_dynsym);
        
            return 0;
        }
        ```
        
    - **Section 정보를 매핑**한다.
        
        ```cpp
        static int load_sections_bfd(bfd *bfd_h, Binary *bin) {
            unsigned int bfd_flags;
            uint64_t vma, size;
            const char *secname;
            asection *bfd_sec;
            Section *sec;
            Section::SectionType sectype;
        		
        		//bfdlib의 sections은 내부적으로 연결리스트로 구현되어있음
            for (bfd_sec = bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next) {
                bfd_flags = bfd_sec->flags;  // bfd_flags = bfd_get_section_flags(bfd_h, bfd_sec);
        				
        				//DATA와 CODE Section의 정보만
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
        				
        				//bfd_h에서 bfd_sec의 내용을 sec->bytes에 복사한다.
                if (!bfd_get_section_contents(bfd_h, bfd_sec, sec->bytes, 0, size)) {
                    fprintf(stderr, "failed to read section '%s' (%s)\n", secname, bfd_errmsg(bfd_get_error()));
                    return -1;
                }
            }
            return 0;
        }
        ```
        
    - **바이너리 파일을 닫는다.**
        
        ```cpp
        if (bfd_h)
                bfd_close(bfd_h);
        ```
        
    
- **전체 소스 코드**
    - inc/loader.cc
        
        ```cpp
        #include "loader.h"
        
        #include <bfd.h>
        
        static bfd *open_bfd(std::string &fname) {
            static int bfd_inited = 0;  // bfd_init()함수를 딱 1번만 호출하기 위함.
            bfd *bfd_h;                 // bfd 라이브러리의 최상위 자료구조, 즉 bfd 파일 타입의 파일 핸들러 포인터
        
            if (!bfd_inited) {
                bfd_init();
                bfd_inited = 1;
            }
        
            bfd_h = bfd_openr(fname.c_str(), NULL);  //두번째 매개변수는 바이너리의 형식을 넘겨줘야한다. NULL이면 자동 판단
            if (!bfd_h) {
                fprintf(stderr, "failed to open binary '%s' (%s)\n", fname.c_str(), bfd_errmsg(bfd_get_error()));
                return NULL;
            }
        
            if (!bfd_check_format(bfd_h, bfd_object)) {  //바이너리의 타입을 확인한다. 실행가능한바이너리, 재배치 가능한 Object파일, Shared Library
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
                } else if(bfd_symtab[i]->flags & BSF_WEAK) {
                    bin->symbols.push_back(Symbol());
                    sym = &bin->symbols.back();
                    sym->type = Symbol::SYM_TYPE_WEAK;
                    sym->name = std::string(bfd_symtab[i]->name);
                    sym->addr = bfd_asymbol_value(bfd_symtab[i]);
                } else if(bfd_symtab[i]->flags & BSF_GLOBAL) {
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
                } else if(bfd_dynsym[i]->flags & BSF_WEAK) {
                    bin->symbols.push_back(Symbol());
                    sym = &bin->symbols.back();
                    sym->type = Symbol::SYM_TYPE_WEAK;
                    sym->name = std::string(bfd_dynsym[i]->name);
                    sym->addr = bfd_asymbol_value(bfd_dynsym[i]);
                } else if(bfd_dynsym[i]->flags & BSF_GLOBAL) {
                    bin->symbols.push_back(Symbol());
                    sym = &bin->symbols.back();
                    sym->type = Symbol::SYM_TYPE_GLOBAL;
                    sym->name = std::string(bfd_dynsym[i]->name);
                    sym->addr = bfd_asymbol_value(bfd_dynsym[i]);
                }
                //BSF_NO_FLAGS
                //BSF_LOCAL
                //BSF_DEBUGGING
                //BSF_KEEP
                //BSF_ELF_COMMON
                //BSF_SECTION_SYM
                //BSF_OLD_COMMON      
                //BSF_NOT_AT_END      
                //BSF_CONSTRUCTOR     
                //BSF_WARNING         
                //BSF_INDIRECT        
                //BSF_FILE            
                //BSF_DYNAMIC         
                //BSF_OBJECT          
                //BSF_DEBUGGING_RELOC 
                //BSF_THREAD_LOCAL    
                //BSF_RELC            
                //BSF_SRELC           
                //BSF_SYNTHETIC       
                //BSF_GNU_INDIRECT_FUN
                //BSF_GNU_UNIQUE      
                //BSF_SECTION_SYM_USED
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
        
            load_symbols_bfd(bfd_h, bin);  //복잡한 과정을 수반하므로 별도의 함수 load_symbol_bfd를 만들어 호출
            load_dynsym_bfd(bfd_h, bin);
        
            if (load_sections_bfd(bfd_h, bin) < 0)
                return -1;
        
            if (bfd_h)
                bfd_close(bfd_h);
            return 0;
        }
        
        int load_binary(std::string &fname, Binary *bin, Binary::BinaryType type) {
            return load_binary_bfd(fname, bin, type);  //복잡한 과정을 수반하므로 별도의 함수 load_binary_bfd를 만들어 호출
        }
        
        void unload_binary(Binary *bin) {
            size_t i;
            for (auto &sec : bin->sections) {
                if (sec.bytes) {
                    free(sec.bytes);  //실제 Section의 크기만큼 할당 받은 메모리. 즉, 실제 Section의 내용
                }
            }
        }
        ```
        
    - loader_demo.cc
        
        ```cpp
        #include <stdint.h>
        #include <stdio.h>
        
        #include <string>
        #include <iostream>
        #include <algorithm>
        #include "../inc/loader.h"
        
        const char* getTypeName(const Symbol::SymbolType& type) {
            if(type == Symbol::SYM_TYPE_FUNC)
                return "FUNC";
            if(type == Symbol::SYM_TYPE_WEAK)
                return "WEAK";
            if(type == Symbol::SYM_TYPE_GLOBAL)
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
        
            auto result = std::find_if(bin.sections.begin(), bin.sections.end(),[&sectionName](const Section& s){return s.name == sectionName;});
            
            if(result != bin.sections.end()) {
                std::cout << "Section Name : "<<(*result).name << std::endl;
                std::cout << "Section size : "<<(*result).size << std::endl;
                std::cout << "Section type : "<<(*result).type << std::endl;
                std::cout << "Section vma : "<<(*result).vma << std::endl;
                //std::cout << "Section Name : "<<(*result).bytes << std::endl;
                for(uint64_t i = 0; i < (*result).size; i++) {
                    printf("%x ",(*result).bytes[i]);
                }
            }
        
            unload_binary(&bin);
        
            return 0;
        }
        ```
        
    
    ```bash
    $ **g++** -lstdc++ -std=c++17 **loader_demo.cc inc/loader.cc** -o loader **-lbfd**
    ```
    
- **연습문제**
    - **섹션 내용 덤프하기**
        
        ![Untitled](4%E1%84%8C%E1%85%A1%E1%86%BC%20LIBBFD%E1%84%85%E1%85%B3%E1%86%AF%20%E1%84%8B%E1%85%B5%E1%84%8B%E1%85%AD%E1%86%BC%E1%84%92%E1%85%A1%E1%86%AB%20%E1%84%87%E1%85%A1%E1%84%8B%E1%85%B5%E1%84%82%E1%85%A5%E1%84%85%E1%85%B5%20%E1%84%85%E1%85%A9%E1%84%83%E1%85%A5%20%E1%84%8C%E1%85%A6%E1%84%8C%E1%85%A1%E1%86%A8%20fab5467dc35143b09bdbf012e3913cb4/Untitled%201.png)
        
        [풀이](https://www.notion.so/a38d289a600f4cf2a38709de603e8d6a)
        
    - **weak 심벌 오버라이드하기**
        
        ![Untitled](4%E1%84%8C%E1%85%A1%E1%86%BC%20LIBBFD%E1%84%85%E1%85%B3%E1%86%AF%20%E1%84%8B%E1%85%B5%E1%84%8B%E1%85%AD%E1%86%BC%E1%84%92%E1%85%A1%E1%86%AB%20%E1%84%87%E1%85%A1%E1%84%8B%E1%85%B5%E1%84%82%E1%85%A5%E1%84%85%E1%85%B5%20%E1%84%85%E1%85%A9%E1%84%83%E1%85%A5%20%E1%84%8C%E1%85%A6%E1%84%8C%E1%85%A1%E1%86%A8%20fab5467dc35143b09bdbf012e3913cb4/Untitled%202.png)
        
        [풀이](https://www.notion.so/c04a67bb51574a199af67470c9577c6b)
        
    - **데이터 심벌 출력하기**
        
        ![Untitled](4%E1%84%8C%E1%85%A1%E1%86%BC%20LIBBFD%E1%84%85%E1%85%B3%E1%86%AF%20%E1%84%8B%E1%85%B5%E1%84%8B%E1%85%AD%E1%86%BC%E1%84%92%E1%85%A1%E1%86%AB%20%E1%84%87%E1%85%A1%E1%84%8B%E1%85%B5%E1%84%82%E1%85%A5%E1%84%85%E1%85%B5%20%E1%84%85%E1%85%A9%E1%84%83%E1%85%A5%20%E1%84%8C%E1%85%A6%E1%84%8C%E1%85%A1%E1%86%A8%20fab5467dc35143b09bdbf012e3913cb4/Untitled%203.png)
        
        [풀이](https://www.notion.so/c0e3daae673e4a1a9e6ab0eca7b3b30c)
