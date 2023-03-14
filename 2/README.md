[Read to Notion](https://bolder-cloud-3a9.notion.site/2-ELF-7e75539fe9fb4bbbafe30f6ec18b5151)
# 2장. ELF 바이너리 포맷

```
**ELF 바이너리 포맷**
├── **ELF Binary Format Overview**
├── **ELF File Header, ELF File Header 분석**
├── **Program Header table(Optional), Program Header table을 참고한 분석**
│   ├── 힙 오버플로우
│   └── 힙 오버플로우 탐지 패치
├── **Sections, Section Header table을 참고한 분석**
│   ├── null section
│   ├── .init / .fini section
│   ├── .text section
│   ├── .bss / .data / .rodata section
│   ├── **지연 바인딩과 .plt / .got / .got.plt section**
│   │   ├── .got / .got.plt의 차이점
****│   │   └── 굳이 .got.plt를 사용하는 이유 2가지
****│   ├── .rel.* / .rela.* section
│   ├── .dynamic section
│   ├── .init_array / .fini_array section
│   └── .shstrab / .symtab / .strtab / .dynsym / .dynstr section
└── **Section Header table(Optional), Section Header table 분석**
```

- **ELF Binary Format Overview**
    
    **ELF** ⇒ **E**xecutable and **L**inkable **F**ormat 64비트 기준으로 설명
    
    **프로그램 헤더 테이블**과 **섹션 헤더 테이블**은 바이너리의 **어느위치에 존재해도 상관 없다.**
    
    그러나 **ELF File Header는 반드시 파일의 시작 부분에 존재**해야한다.
    
    ![Untitled](https://user-images.githubusercontent.com/104804087/224589314-06659a1c-e817-465f-8db0-3eee801c1e58.png)

   

---

- **ELF File Header**
    
    모든 ELF 파일은 Executable header로 시작하며, ELF 파일임을 나타내는 정형화된 바이트 배치와 ELF파일의 종류가`/usr/include/elf.h` 에명시되어있다.
    
    ```c
    #define EI_NIDENT (16)
    
    typedef struct
    {
      unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
      Elf64_Half	e_type;			/* Object file type */
      Elf64_Half	e_machine;		/* Architecture */
      Elf64_Word	e_version;		/* Object file version */
      Elf64_Addr	e_entry;		/* Entry point virtual address */
      Elf64_Off	e_phoff;		/* Program header table file offset */
      Elf64_Off	e_shoff;		/* Section header table file offset */
      Elf64_Word	e_flags;		/* Processor-specific flags */
      Elf64_Half	e_ehsize;		/* ELF header size in bytes */
      Elf64_Half	e_phentsize;		/* Program header table entry size */
      Elf64_Half	e_phnum;		/* Program header table entry count */
      Elf64_Half	e_shentsize;		/* Section header table entry size */
      Elf64_Half	e_shnum;		/* Section header table entry count */
      Elf64_Half	e_shstrndx;		/* Section header string table index */
    } Elf64_Ehdr;
    ```
    
     
    

- **ELF File Header 분석**
    
    ```bash
    **[-h|--file-header] #Elf File Header 출력**
    
    **$ readelf -h a.out** 
    ELF Header:
      Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
      Class:                             **ELF64**
      Data:                              2's complement, **little endian**
      Version:                           **1 (current)**
      OS/ABI:                            **UNIX - System V**
      ABI Version:                       **0**
      Type:                              **EXEC (Executable file)**
      Machine:                           Advanced Micro Devices X86-64
      Version:                           0x1 (current)
      **Entry point address:               0x401050 #Virtual Address**
      Start of program headers:          **64 (bytes into file) #File Offset**
      Start of section headers:          **13912 (bytes into file) #File Offset**
      Flags:                             0x0
      Size of this header:               64 (bytes)
      Size of program headers:           56 (bytes)
      Number of program headers:         13
      Size of section headers:           64 (bytes)
      Number of section headers:         31
      **Section header string table index: 30 => .shstrtab Section Header의 인덱스 정보**
    ```
    
    - **e_ident[16]**
        
        여러가지 기본적인 정보를 저장하고있는 배열
        
      ![Untitled 1](https://user-images.githubusercontent.com/104804087/224589381-898e8d29-bb70-4a0d-aaa8-c571910c4a1f.png)

        0x7f, 0x45, 0x4C, 0x46으로 Magic code로 시작한다.
        
    - **e_type**
        
        바이너리 파일의 형식
        
        **ET_REL** : 재배치 가능한 Object 파일
        
        **ET_EXEC** : 실행 가능한 바이너리 파일
        
        **ET_DYN** : 동적 라이브러리 또는 Shared Object File
        
    - **e_machine**
        
        해당 바이너리 파일이 실행될 아키텍쳐 환경
        
        EM_X86_64 : 인텔 64비트 x86 머신
        
        EM_386 : 인텔 32비트 x86 머신
        
        EM_ARM : ARM 머신
        
    - **e_version**
        
        ELF 명세 버전 e_ident의 EI_VERSION 필드와 똑같다.
        
        EV_CURRENT : 1, 첫 번째 버전의 명세서 
        
    - **e_entry**
        
        해당 바이너리 파일의 **엔트리 포인트 가상 메모리 주소**
        
        바이너리 파일이 .interp Section을 통해 인터프리터를 결정하고 커널이 인터프리터에게 제어권한을 넘긴후 (인터프리터가) 바이너리 파일을 가상 메모리에 적재하고 이 지점으로 이동한다. 
        
        **0x401050 _start 함수의 주소**
        
    - **e_phoff**
        
        프로그램 헤더 테이블(Program Header table)의 **파일 오프셋**, 존재하지 않는 경우 0
        
    - **e_shoff**
        
        섹션 헤더 테이블(Section Header table)의 **파일 오프셋**, 존재하지 않는 경우 0
        
    - **e_flags**
        
        해당 바이너리가 **컴파일된 아키텍쳐의 정보(예를들어 ARM인경우 ARM과 관련한 플래그를 저장하고 이를 통해 임베디드 OS의 인터페이스를 예측한다.)**를 나타내는 플래그
        
        인텔 x86 바이너리의 경우 0
        
    - **e_ehsize**
        
        ELF File Header의 크기
        
        64비트인 경우 **64바이트**
        
        32비트인 경우 **52바이트**
        
    - **e_phentsize, e_phnum**
        
        프로그램 헤더**(Program Header)** **각각의 크기**와 **개수**
        
    - **e_shentsize, e_shnum**
        
        **Section Header** **각각의 크기**와 **개수**
        
    - **e_shstrndx**
        
        **Section Header table**중 **.shstrtab Section Header의 인덱스 정보**
        
        .shstrtabe Section은 바이너리 내부에 존재하는 모든 Section의 이름정보를 저장하고있음.
        
        ```bash
        **[-x <number or name>|--hex-dump=<number or name>]**
        
        **$ readelf -x .shstrtab a.out**
        
        Hex dump of section '.shstrtab':
          0x00000000 002e7379 6d746162 002e7374 72746162 ..symtab..strtab
          0x00000010 002e7368 73747274 6162002e 696e7465 ..shstrtab..inte
          0x00000020 7270002e 6e6f7465 2e676e75 2e70726f rp..note.gnu.pro
          0x00000030 70657274 79002e6e 6f74652e 676e752e perty..note.gnu.
          0x00000040 6275696c 642d6964 002e6e6f 74652e41 build-id..note.A
          0x00000050 42492d74 6167002e 676e752e 68617368 BI-tag..gnu.hash
          0x00000060 002e6479 6e73796d 002e6479 6e737472 ..dynsym..dynstr
          0x00000070 002e676e 752e7665 7273696f 6e002e67 ..gnu.version..g
          0x00000080 6e752e76 65727369 6f6e5f72 002e7265 nu.version_r..re
          0x00000090 6c612e64 796e002e 72656c61 2e706c74 la.dyn..rela.plt
          0x000000a0 002e696e 6974002e 706c742e 73656300 ..init..plt.sec.
          0x000000b0 2e746578 74002e66 696e6900 2e726f64 .text..fini..rod
          0x000000c0 61746100 2e65685f 6672616d 655f6864 ata..eh_frame_hd
          0x000000d0 72002e65 685f6672 616d6500 2e696e69 r..eh_frame..ini
          0x000000e0 745f6172 72617900 2e66696e 695f6172 t_array..fini_ar
          0x000000f0 72617900 2e64796e 616d6963 002e676f ray..dynamic..go
          0x00000100 74002e67 6f742e70 6c74002e 64617461 t..got.plt..data
          0x00000110 002e6273 73002e63 6f6d6d65 6e7400   ..bss..comment.
        
        **$ readelf -x 30 out_not_strip**       
        
        Hex dump of section '.shstrtab':
          0x00000000 002e7379 6d746162 002e7374 72746162 ..symtab..strtab
          0x00000010 002e7368 73747274 6162002e 696e7465 ..shstrtab..inte
          0x00000020 7270002e 6e6f7465 2e676e75 2e70726f rp..note.gnu.pro
          0x00000030 70657274 79002e6e 6f74652e 676e752e perty..note.gnu.
          0x00000040 6275696c 642d6964 002e6e6f 74652e41 build-id..note.A
          0x00000050 42492d74 6167002e 676e752e 68617368 BI-tag..gnu.hash
          0x00000060 002e6479 6e73796d 002e6479 6e737472 ..dynsym..dynstr
          0x00000070 002e676e 752e7665 7273696f 6e002e67 ..gnu.version..g
          0x00000080 6e752e76 65727369 6f6e5f72 002e7265 nu.version_r..re
          0x00000090 6c612e64 796e002e 72656c61 2e706c74 la.dyn..rela.plt
          0x000000a0 002e696e 6974002e 706c742e 73656300 ..init..plt.sec.
          0x000000b0 2e746578 74002e66 696e6900 2e726f64 .text..fini..rod
          0x000000c0 61746100 2e65685f 6672616d 655f6864 ata..eh_frame_hd
          0x000000d0 72002e65 685f6672 616d6500 2e696e69 r..eh_frame..ini
          0x000000e0 745f6172 72617900 2e66696e 695f6172 t_array..fini_ar
          0x000000f0 72617900 2e64796e 616d6963 002e676f ray..dynamic..go
          0x00000100 74002e67 6f742e70 6c74002e 64617461 t..got.plt..data
          0x00000110 002e6273 73002e63 6f6d6d65 6e7400   ..bss..comment.
        ```
        

---

- **Section Header table(Optional)**
    
    Section에 관한 모든 속성들을 정의
    
    **Section**은 링커 / 정적 분석 도구가 바이너리를 해석할때 편리한 단위로 나눈것이다. ⇒ Process형태로 메모리에 적재될때에는 Section의 정보는 중요하지 않다.(기호 정보/재배치 관련 정보는 실행시점에서는 전혀 참조하지 않는다.)
    
    즉, **Section**은 **링킹 단계 또는 정적 분석 단계**에서만 중요한 의미를 가진다.
    
    ```c
    typedef struct
    {
      Elf64_Word	sh_name;		/* Section name (string tbl index) */
      Elf64_Word	sh_type;		/* Section type */
      Elf64_Xword	sh_flags;		/* Section flags */
      Elf64_Addr	sh_addr;		/* Section virtual addr at execution */
      Elf64_Off	sh_offset;		/* Section file offset */
      Elf64_Xword	sh_size;		/* Section size in bytes */
      Elf64_Word	sh_link;		/* Link to another section */
      Elf64_Word	sh_info;		/* Additional section information */
      Elf64_Xword	sh_addralign;		/* Section alignment */
      Elf64_Xword	sh_entsize;		/* Entry size if section holds table */
    } Elf64_Shdr;
    ```
    

- **Section Header table 분석**
    
    ```bash
    **$ readelf --sections --wide a.out** 
    There are 31 section headers, starting at offset 0x3658:
    
    Section Headers:
      [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
      [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
      [ 1] .interp           PROGBITS        0000000000400318 000318 00001c 00   A  0   0  1
      [ 2] .note.gnu.property NOTE           0000000000400338 000338 000030 00   A  0   0  8
      [ 3] .note.gnu.build-id NOTE           0000000000400368 000368 000024 00   A  0   0  4
      [ 4] .note.ABI-tag     NOTE            000000000040038c 00038c 000020 00   A  0   0  4
      [ 5] .gnu.hash         GNU_HASH        00000000004003b0 0003b0 00001c 00   A  6   0  8
      [ 6] .dynsym           DYNSYM          00000000004003d0 0003d0 000060 18   A  7   1  8
      [ 7] .dynstr           STRTAB          0000000000400430 000430 000048 00   A  0   0  1
      [ 8] .gnu.version      VERSYM          0000000000400478 000478 000008 02   A  6   0  2
      [ 9] .gnu.version_r    VERNEED         0000000000400480 000480 000030 00   A  7   1  8
      [10] .rela.dyn         RELA            00000000004004b0 0004b0 000030 18   A  6   0  8
      [11] .rela.plt         RELA            00000000004004e0 0004e0 000018 18  AI  6  24  8
      [12] .init             PROGBITS        0000000000401000 001000 00001b 00  AX  0   0  4
      [13] .plt              PROGBITS        0000000000401020 001020 000020 10  AX  0   0 16
      [14] .plt.sec          PROGBITS        0000000000401040 001040 000010 10  AX  0   0 16
      [15] .text             PROGBITS        0000000000401050 001050 00010f 00  AX  0   0 16
      [16] .fini             PROGBITS        0000000000401160 001160 00000d 00  AX  0   0  4
      [17] .rodata           PROGBITS        0000000000402000 002000 000012 00   A  0   0  4
      [18] .eh_frame_hdr     PROGBITS        0000000000402014 002014 000034 00   A  0   0  4
      [19] .eh_frame         PROGBITS        0000000000402048 002048 0000a4 00   A  0   0  8
      [20] .init_array       INIT_ARRAY      0000000000403e10 002e10 000008 08  WA  0   0  8
      [21] .fini_array       FINI_ARRAY      0000000000403e18 002e18 000008 08  WA  0   0  8
      [22] .dynamic          DYNAMIC         0000000000403e20 002e20 0001d0 10  WA  7   0  8
      [23] .got              PROGBITS        0000000000403ff0 002ff0 000010 08  WA  0   0  8
      [24] .got.plt          PROGBITS        0000000000404000 003000 000020 08  WA  0   0  8
      [25] .data             PROGBITS        0000000000404020 003020 000010 00  WA  0   0  8
      [26] .bss              NOBITS          0000000000404030 003030 000008 00  WA  0   0  1
      [27] .comment          PROGBITS        0000000000000000 003030 000026 01  MS  0   0  1
      [28] .symtab           SYMTAB          0000000000000000 003058 000330 18     29  18  8
      [29] .strtab           STRTAB          0000000000000000 003388 0001af 00      0   0  1
      [30] .shstrtab         STRTAB          0000000000000000 003537 00011f 00      0   0  1
    Key to Flags:
      W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
      L (link order), O (extra OS processing required), G (group), T (TLS),
      C (compressed), x (unknown), o (OS specific), E (exclude),
      D (mbind), l (large), p (processor specific)
    ```
    
    - **sh_name**
        
        .shstrtab 문자열 테이블 상의 인덱스; Section Header의 이름
        
        0이라면 별도의 이름을 가지고 있지 않다.
        
        - 정적 분석 도구가 Section의 이름을 알아내는 알고리즘
            
            ```c
            1. File Header에서 Section Header table의 시작 오프셋을 알아낸다.
            Start of section headers: **13912 (bytes into file) #File Offset**
            
            2. 각 Section Header의 크기와 개수를 알아낸다. 
            Size of section headers: **64 (bytes)**
            Number of section headers: **31**
            
            3. .shstrtab Section Header의 인덱스를 알아낸다.
            **Section header string table index: 30** 
            
            ****while(모든 Section Header를 순회하지 않았다면) {
            	****4. Section Header table을 순회하면서 sh_name값을 읽는다.
            
            	****5. Section Header table의 30번째 인덱스로 접근 : .shstrtab Section Header
            
            	6. .shstrtab Section Header의 File Offset값을 읽는다.(실제 위치)
            
            	7. sh_name 값이 인덱스에 접근해 이름을 읽는다.
            }
            ```
            
    - **sh_type**
        
        **SHT_PROGBITS : 특별한 구조를 가지지 않고, 기계어 명령, 상수값 등의 프로그램의 데이터**
        
        **SHT_SYMTAB** : **정적 링킹을 위한 Symbol 테이블** **Section** ⇒ 바이너리가 Stripped된 상태라면 정적 Symbol 테이블 Section은 존재하지 않는다.
        
        **SHT_DYNSYM** : **동적 링킹을 위한 Symbol 테이블** **Section**
        
        **SHT_STRTAB** : **Symbol의 실제 이름을 저장하는 문자열 테이블 Section** : NULL문자로 시작하는 C Style Array 배열
        
        SHT_REL / SHT_RELA : **정적 링킹**을 위한 **재배치가 필요한 부분의 주소**, **해결해야하는 Symbol의 정보**
        
        SHT_DYNAMIC : **동적 링킹**을 위한 정보
        
        SHT_NULL : ELF Section Header의 첫번째 항목
        
    - **sh_flags**
        
        섹션의 추가 플래그 정보
        
        **SHF_WRITE** : **실행 시점**에서 **현재 Section이 쓰기 가능**한 상태(즉, 해당 Section의 명령어는 쓰기작업 가능)( 정적 데이터에 해당하는 Section(쓰기x) / **변수 값을 저장하는 Section(SHF_WRITE)** 구별 가능)
        
        **SHF_ALLOC** : **실행 시점**에서 **현재 Section**이 **가상 메모리에 적재**
        
        **SHF_EXECINSTR** : **현재 Section**이 **실행 가능한 명령어들을 담고 있는 Section**
        
    - **sh_addr**
        
        현재 Section의 **가상 메모리 주소**
        
        Section정보는 오직 링킹 단계 에서만 사용되는데 가상 메모리 주소값이 존재하는 이유는 실행 시점에서 특정 코드 혹은 데이터가 끝나는 위치의 주소를 알고 있어야 링커가 재배치 작업을 수행 할 수 있는 경우가있다. 이러한 과정이 불필요 하다면 0
        
    - **sh_offset**
        
        현재 Section의 **파일 오프셋**
        
    - **sh_size**
        
        현재 Section의 **크기**
        
    - **sh_link**
        
        각 Section사이의 연관 관계 정보 : Section Header table상의 인덱스 정보를 저장한다.
        
    - **sh_info**
        
        Section과 관련된 추가 정보 : Section Header table상의 인덱스 정보를 저장한다.
        
    - **sh_addralign**
        
        Section들이 메모리상에 배치될때(Segment) 메모리 접근의 효율성을 위한 배수값 설정 필드
        
        0 또는 1이라면 별도의 배치 규칙이 존재하지 않는다. 16이라면 16바이트의 배수로 설정
        
    - **sh_entsize**
        
        Symbol table, 재배치 table과 같은 형식이 정해진 Section의 경우 해당 table의 각 entry들의 크기정의, 사용 하지 않는 경우 0
        
- **Sections, Section Header table을 참고한 분석**
    
    실제 ELF의 Section 구성
    
    ```bash
    **$ readelf --sections --wide out_not_strip** 
    There are 31 section headers, starting at offset 0x3658:
    
    Type : 현재 Section의 유형 정보
    ES : sh_entsize(현재 section table의 각 entry의 크기)
    Flg : sh_flags(섹션의 추가정보 : 쓰기(W)/메모리 적재(A)/실행 가능 명령어(X))
    Lk : sh_link(각 Section사이의 연관 관계 정보)
    Inf : sh_info(Section과 관련된 추가 정보)
    Al : sh_addralign(메모리 접근 효율성을 위한 배수값)
    
    Section Headers:
    [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
    **[ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0**
    [ 1] .interp           PROGBITS        0000000000400318 000318 00001c 00   A  0   0  1
    [ 2] .note.gnu.property NOTE           0000000000400338 000338 000030 00   A  0   0  8
    [ 3] .note.gnu.build-id NOTE           0000000000400368 000368 000024 00   A  0   0  4
    [ 4] .note.ABI-tag     NOTE            000000000040038c 00038c 000020 00   A  0   0  4
    [ 5] .gnu.hash         GNU_HASH        00000000004003b0 0003b0 00001c 00   A  6   0  8
    [ 6] .dynsym           DYNSYM          00000000004003d0 0003d0 000060 18   A  7   1  8
    [ 7] .dynstr           STRTAB          0000000000400430 000430 000048 00   A  0   0  1
    [ 8] .gnu.version      VERSYM          0000000000400478 000478 000008 02   A  6   0  2
    [ 9] .gnu.version_r    VERNEED         0000000000400480 000480 000030 00   A  7   1  8
    [10] .rela.dyn         RELA            00000000004004b0 0004b0 000030 18   A  6   0  8
    [11] .rela.plt         RELA            00000000004004e0 0004e0 000018 18  AI  6  24  8
    [12] .init             PROGBITS        0000000000401000 001000 00001b 00  AX  0   0  4
    [13] .plt              PROGBITS        0000000000401020 001020 000020 10  AX  0   0 16
    [14] .plt.sec          PROGBITS        0000000000401040 001040 000010 10  AX  0   0 16
    [15] .text             PROGBITS        0000000000401050 001050 000104 00  AX  0   0 16
    [16] .fini             PROGBITS        0000000000401154 001154 00000d 00  AX  0   0  4
    [17] .rodata           PROGBITS        0000000000402000 002000 000012 00   A  0   0  4
    [18] .eh_frame_hdr     PROGBITS        0000000000402014 002014 000034 00   A  0   0  4
    [19] .eh_frame         PROGBITS        0000000000402048 002048 0000a4 00   A  0   0  8
    [20] .init_array       INIT_ARRAY      0000000000403e10 002e10 000008 08  WA  0   0  8
    [21] .fini_array       FINI_ARRAY      0000000000403e18 002e18 000008 08  WA  0   0  8
    [22] .dynamic          DYNAMIC         0000000000403e20 002e20 0001d0 10  WA  7   0  8
    [23] .got              PROGBITS        0000000000403ff0 002ff0 000010 08  WA  0   0  8
    [24] .got.plt          PROGBITS        0000000000404000 003000 000020 08  WA  0   0  8
    [25] .data             PROGBITS        0000000000404020 003020 000010 00  WA  0   0  8
    [26] .bss              NOBITS          0000000000404030 003030 000008 00  WA  0   0  1
    [27] .comment          PROGBITS        0000000000000000 003030 00002b 01  MS  0   0  1
    [28] .symtab           SYMTAB          0000000000000000 003060 000330 18     29  18  8
    [29] .strtab           STRTAB          0000000000000000 003390 0001a3 00      0   0  1
    [30] .shstrtab         STRTAB          0000000000000000 003533 00011f 00      0   0  1
    Key to Flags:
      W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
      L (link order), O (extra OS processing required), G (group), T (TLS),
      C (compressed), x (unknown), o (OS specific), E (exclude),
      D (mbind), l (large), p (processor specific)
    ```
    
    - **null section**
        
        **Section Header table의 첫번째 항목**은 ELF 표준에 의해 NULL
        
        ```bash
        Section Headers:
          [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
          **[ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0**
        ```
        
        이 Section의 모든 필드값은 0
        
    - **.init / .fini section**
        
        ```bash
        Section Headers:
        Type : 현재 Section의 유형 정보
        ES : sh_entsize(현재 section table의 각 entry의 크기)
        Flg : sh_flags(섹션의 추가정보 : **쓰기(W)/메모리 적재(A)/실행 가능 명령어(X)**)
        Lk : sh_link(각 Section사이의 연관 관계 정보)
        Inf : sh_info(Section과 관련된 추가 정보)
        Al : sh_addralign(메모리 접근 효율성을 위한 배수값)
        [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
        **[12] .init             PROGBITS        0000000000401000 001000 00001b 00  AX  0   0  4
        #메모리 적재(A)/실행가능명령어(X)
        [16] .fini             PROGBITS        0000000000401154 001154 00000d 00  AX  0   0  4**
        ```
        
        **.init Section**은 인터프리터가 바이너리파일을 실행할때 가장 먼저 실행되는 Section, **초기화 작업을 수행**하며 바이너리의 다른코드를 실행하기전 **선행 실행코드**를 포함
        
        **.fini Section**은 메인 프로그램의 실행이 완전히 종료된 후 실행
        
        sh_type값은 **SHT_PROGBITS : 특별한 구조를 가지지 않고, 기계어 명령, 상수값 등의 프로그램의 데이터**
        
    - **.text section**
        
        ```bash
        Section Headers:
        Type : 현재 Section의 유형 정보
        ES : sh_entsize(현재 section table의 각 entry의 크기)
        Flg : sh_flags(섹션의 추가정보 : **쓰기(W)/메모리 적재(A)/실행 가능 명령어(X)**)
        Lk : sh_link(각 Section사이의 연관 관계 정보)
        Inf : sh_info(Section과 관련된 추가 정보)
        Al : sh_addralign(메모리 접근 효율성을 위한 배수값)
        [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
        **[15] .text             PROGBITS        0000000000401050 001050 00010f 00  AX  0   0 16
        #메모리 접근 배수 16바이트, 메모리 적재(A)/실행가능명령어(X)**
        ```
        
        main 함수 코드가 존재하는 역공학 수행의 주요 목표물
        
        **실행가능한 Section은 Write할 수 있으면 안된다**. ⇒ 만약 실행 가능한 Section의 코드에서 읽기 전용 Section에 코드에 Write해 ROP 공격을 할 수 있기 때문이다.
        
        Write 할 수 있는 Section은 실행하면 안된다.(Stack에 직접 쉘코드를 삽입하고 RIP값을 조작해 Stack을 실행 하는 공격 등)
        
        _**start함수**, register_tm_clones함수, frame_dummy함수등 여러 가지 표준 함수 포함하는 Section
        
        sh_type값은 **SHT_PROGBITS : 특별한 구조를 가지지 않고, 기계어 명령, 상수값 등의 프로그램의 데이터**
        
        ```bash
        **$ objdump -M intel -d a.out** 
        
        a.out:     file format elf64-x86-64
        
        Disassembly of section .text:
        
        **0000000000401050 <_start>: # Entry Point**
          401050:	f3 0f 1e fa          	endbr64 
          401054:	31 ed                	xor    ebp,ebp
          401056:	49 89 d1             	mov    r9,rdx
          401059:	5e                   	pop    rsi
          40105a:	48 89 e2             	mov    rdx,rsp
          40105d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
          401061:	50                   	push   rax
          401062:	54                   	push   rsp
          401063:	45 31 c0             	xor    r8d,r8d
          401066:	31 c9                	xor    ecx,ecx
          **401068:	48 c7 c7 36 11 40 00 	mov    rdi,0x401136 # main 함수의 주소 매개변수로 전달**
          **40106f:	ff 15 7b 2f 00 00    	call   QWORD PTR [rip+0x2f7b]        
        											# 403ff0 <__libc_start_main@GLIBC_2.34>**
          401075:	f4                   	hlt    
          401076:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
          40107d:	00 00 00
        
        ...
        
        0000000000401136 <main>:
          401136:	f3 0f 1e fa          	endbr64 
          40113a:	55                   	push   rbp
          40113b:	48 89 e5             	mov    rbp,rsp
          40113e:	48 83 ec 10          	sub    rsp,0x10
          401142:	89 7d fc             	mov    DWORD PTR [rbp-0x4],edi
          401145:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
          401149:	48 8d 05 b4 0e 00 00 	lea    rax,[rip+0xeb4]        # 402004 <_IO_stdin_used+0x4>
          401150:	48 89 c7             	mov    rdi,rax
          **401153:	e8 e8 fe ff ff       	call   401040 <puts@plt> 
        																; puts는 plt Section에 존재=> 공유 라이브러리의 일부!**
          401158:	b8 00 00 00 00       	mov    eax,0x0
          40115d:	c9                   	leave  
          40115e:	c3                   	ret
        
        **$ objdump -M intel -j .plt.sec -d out_not_strip**
        
        out_not_strip:     file format elf64-x86-64
        
        Disassembly of section **.plt.sec:**
        
        0000000000401040 <puts@plt>:
          401040:	f3 0f 1e fa          	endbr64 
          401044:	f2 ff 25 cd 2f 00 00 	bnd jmp QWORD PTR [rip+0x2fcd]        # 404018 <puts@GLIBC_2.2.5>
        #0x00007ffff7c80ed0 동적 링커가 puts 함수 주소를 여기(.plt, 0x404018)에 저장한다.
          40104b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
        
        **$ objdump -M intel -j .got.plt -d out_not_strip**
        
        out_not_strip:     file format elf64-x86-64
        
        Disassembly of section **.got.plt:**
        
        0000000000404000 <_GLOBAL_OFFSET_TABLE_>:
          404000:	20 3e 40 00 00 00 00 00 00 00 00 00 00 00 00 00      >@.............
        	...
          404018:	**30 10 40 00** 00 00 00 00                             0.@.....
        
        **$ objdump -M intel -j .plt -d out_not_strip**
        
        out_not_strip:     file format elf64-x86-64
        
        Disassembly of section .plt:
        
        0000000000401020 <.plt>:
        #0x00007ffff7ffe2e0 -> 특별한 매개변수인듯?
          401020:	ff 35 e2 2f 00 00    	push   QWORD PTR [rip+0x2fe2]        **# 404008 <_GLOBAL_OFFSET_TABLE_+0x8>(.got.plt)
        #bnd jmp QWORD PTR [rip+0x2fe3] 여기서 동적링커(_dl_runtime_resolve_xsavec) 호출 하고 4**04018 <puts@GLIBC_2.2.5> 여기에 puts주소 할당
        **#0x00007ffff7fd8d30 -> _dl_runtime_resolve_xsavec**
        #따라서 인터프리터가 최초에 puts 주소를 할당하면 다음번에는 바로 puts함수 호출
          401026:	f2 ff 25 e3 2f 00 00 	bnd jmp QWORD PTR [rip+0x2fe3]        # 404010 <_GLOBAL_OFFSET_TABLE_+0x10>(.got.plt)
          40102d:	0f 1f 00             	nop    DWORD PTR [rax]
          **401030:	f3 0f 1e fa          	endbr64** 
          401034:	68 00 00 00 00       	push   0x0
          401039:	f2 e9 e1 ff ff ff    	bnd jmp 401020 <_init+0x20>
          40103f:	90                   	nop
        ```
        
    - **.bss / .data / .rodata section**
        
        ```bash
        Section Headers:
        Type : 현재 Section의 유형 정보
        ES : sh_entsize(현재 section table의 각 entry의 크기)
        Flg : sh_flags(섹션의 추가정보 : **쓰기(W)/메모리 적재(A)/실행 가능 명령어(X)**)
        Lk : sh_link(각 Section사이의 연관 관계 정보)
        Inf : sh_info(Section과 관련된 추가 정보)
        Al : sh_addralign(메모리 접근 효율성을 위한 배수값)
        [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
        [**26] .bss              NOBITS          0000000000404030 003030 000008 00  WA  0   0  1
        # 메모리 정렬 없음 : 쓰기(W)/메모리 적재(A)
        # 초기화 되지 않은 변수들**을 위해 **예약된 공간
        # SHT_NOBITS ⇒ 초기화 되지 않은 변수**들이기 때문에 **디스크에 존재하며 아무런 바이트도 점유하지 않는다.
        # 그러나** 실제 **Segment로 가상 메모리에 적재** 될때는 **크기가 존재**한다. **0으로 초기화되며 쓰기가능하다.
        [25] .data             PROGBITS        0000000000404020 003020 000010 00  WA  0   0  8
        # 메모리 정렬 8바이트 : 쓰기(W)/메모리 적재(A)
        # 초기화된 변수의 기본값이 저장, 쓰기 가능한 공간
        [17] .rodata           PROGBITS        0000000000402000 002000 000012 00   A  0   0  4
        # 메모리 정렬 4바이트 : 메모리 적재(A)
        # read-only 데이터**를 관리하는 공간, **상수 값 저장,** 쓰기가 불가능하다.
        ```
        
        sh_type값은 **SHT_PROGBITS : 특별한 구조를 가지지 않고, 기계어 명령, 상수값 등의 프로그램의 데이터**
        
    - **지연 바인딩과 .plt .plt.sec / .got / .got.plt section**
        
        **-fno-builtin 옵션**
        
        ```bash
        Section Headers:
        [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
        **GOT Section
        [23] .got              PROGBITS        0000000000403ff0 002ff0 000010 08  WA  0   0  8
        [24] .got.plt          PROGBITS        0000000000404000 003000 000020 08  WA  0   0  8
        # 쓰기(W) / 메모리 적재(A) Entry Size = 8
        PLT Section
        [13] .plt              PROGBITS        0000000000401020 001020 000020 10  AX  0   0 16**
        [14] .plt.sec          PROGBITS        0000000000401040 001040 000010 10  AX  0   0 16
        **# 메모리 적재(A) / 실행 가능 명령어(X)**
        ```
        
        - 리눅스의 지연바인딩 원리
        
        ![Untitled 2](https://user-images.githubusercontent.com/104804087/224589427-fbb23e02-bb38-4c51-a8f1-4d106b24a8d5.png)

        ```bash
        $ objdump -M intel -d out_not_strip_test
        중략..
        0000000000401136 <main>:
          401136:	f3 0f 1e fa          	endbr64 
          40113a:	55                   	push   rbp
          40113b:	48 89 e5             	mov    rbp,rsp
          40113e:	48 8d 05 bf 0e 00 00 	lea    rax,[rip+0xebf]        # 402004 <_IO_stdin_used+0x4>
          401145:	48 89 c7             	mov    rdi,rax
          **401148:	e8 f3 fe ff ff       	call   401040 <puts@plt> -> .plt.sec**
          40114d:	48 8d 05 b0 0e 00 00 	lea    rax,[rip+0xeb0]        # 402004 <_IO_stdin_used+0x4>
          401154:	48 89 c7             	mov    rdi,rax
          **401157:	e8 e4 fe ff ff       	call   401040 <puts@plt> -> .plt.sec**
          40115c:	b8 00 00 00 00       	mov    eax,0x0
          401161:	5d                   	pop    rbp
          401162:	c3                   	ret
        
        **$ objdump -M intel -j .plt.sec -d out_not_strip_test**
        
        out_not_strip_test:     file format elf64-x86-64
        
        Disassembly of section .plt.sec:
        
        **0000000000401040 <puts@plt>:**
          401040:	f3 0f 1e fa          	endbr64 
          401044:	f2 ff 25 cd 2f 00 00 	bnd **jmp QWORD PTR [rip+0x2fcd] ->.got.plt ->puts** **# 404018 <puts@GLIBC_2.2.5>**
          40104b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
        
        **$ objdump -M intel -j .got.plt -d out_not_strip_test**
        
        out_not_strip_test:     file format elf64-x86-64
        
        Disassembly of section .got.plt:
        
        0000000000404000 <_GLOBAL_OFFSET_TABLE_>:
          404000:	20 3e 40 00 00 00 00 00 00 00 00 00 00 00 00 00      >@.............
        	...
          **404018:	30 10 40 00 00 00 00 00  ->.plt**                      0.@.....
        **$ objdump -M intel -j .plt -d out_not_strip_test**
        
        out_not_strip_test:     file format elf64-x86-64
        
        Disassembly of section .plt:
        
        0000000000401020 <.plt>:
        # 필요한 매개변수 값(push 0, 1, 2, 3, ... 각각의 함수를 구별하기위한값)
          401020:	ff 35 e2 2f 00 00    	push   QWORD PTR [rip+0x2fe2]        # 404008 <_GLOBAL_OFFSET_TABLE_+0x8>
        **# 0x404010에는 동적 링커의 주소가 저장되어 있음 -> 동적 링커 호출**
          **401026:	f2 ff 25 e3 2f 00 00 	bnd jmp QWORD PTR [rip+0x2fe3]        # 404010 <_GLOBAL_OFFSET_TABLE_+0x10>**
          40102d:	0f 1f 00             	nop    DWORD PTR [rax]
          **401030:	f3 0f 1e fa          	endbr64** 
          401034:	68 00 00 00 00       	push   0x0 #.plt 함수 호출에 대한 호출 stack
          401039:	f2 e9 e1 ff ff ff    	bnd jmp 401020 <_init+0x20>
          40103f:	90                   	nop
        
        # 여러개의 plt가 존재하면 push 0, 1, 2 계속 증가..
        Disassembly of section .plt:
        
        0000000000401020 <.plt>:
          401020:	ff 35 e2 2f 00 00    	push   QWORD PTR [rip+0x2fe2]        # 404008 <_GLOBAL_OFFSET_TABLE_+0x8>
          401026:	f2 ff 25 e3 2f 00 00 	bnd jmp QWORD PTR [rip+0x2fe3]        # 404010 <_GLOBAL_OFFSET_TABLE_+0x10>
          40102d:	0f 1f 00             	nop    DWORD PTR [rax]
          401030:	f3 0f 1e fa          	endbr64 
          401034:	68 00 00 00 00       	push   0x0
          401039:	f2 e9 e1 ff ff ff    	bnd jmp 401020 <_init+0x20>
          40103f:	90                   	nop
          401040:	f3 0f 1e fa          	endbr64 
          401044:	68 01 00 00 00       	push   0x1
          401049:	f2 e9 d1 ff ff ff    	bnd jmp 401020 <_init+0x20>
          40104f:	90                   	nop
          401050:	f3 0f 1e fa          	endbr64 
          401054:	68 02 00 00 00       	push   0x2
          401059:	f2 e9 c1 ff ff ff    	bnd jmp 401020 <_init+0x20>
          40105f:	90                   	nop
        ```
        
        - **.got / .got.plt의 차이점**
            
            **.got section**은 공유 라이브러리에서 추출된 **데이터 항목에 대한 참조**이며
            
            **.got.plt section**은 plt를 통해 호출되는 **라이브러리 함수에 대한 참조 주소**이다.
            
            |  | Section 이름 | 역할 | Flags | 비고 |
            | --- | --- | --- | --- | --- |
            | GOT | .got.plt | Shared Library의 Function의 참조 주소 저장 table | WA(쓰기, 메모리 적재O) | .plt를 거쳐 사용 |
            | GOT | .got | Shared Library의 Symbol Data 참조 주소 저장 table | WA(쓰기, 메모리 적재O) | 바로 접근 |
            | PLT | .plt | 지연 바인딩을 구현하는 procedure | AX(메모리 적재O,  실행가능) |  |
        - **굳이 .got.plt를 사용하는 이유 2가지**
            1. **.got section에 참조 주소 정보등을 분리** 함으로써 간접점프를 수행하게해 위협을 완화한다.
            .got 섹션을 수정하여 프로그램의 메모리 공간에 이미 존재하는 일련의 작은 코드 조각으로 제어 흐름을 리디렉션하는 반환 지향 프로그래밍(ROP) 공격을 사용할 가능성을 제한할 수 있습니다. .got 섹션을 분리하면 프로그램의 제어 흐름 무결성을 더 잘 유지할 수 있으므로 공격자가 ROP 공격을 활용하기가 더 어려워집니다.
            2. 최신 OS는 Shared Library 개념을 사용해 각 process의 가상메모리에 해당 Shared Library를 가상주소로 Mapping 한다. 따라서 .got table을 각 process마다 가져 Linker는 이 table만 patch한다. 따라서 해커가 다른 process에서 계산한 참조 주소값을 코드에 직접 패치 할 수 없다.
            
            2. 공유 라이브러리를 사용하기 위함 ⇒ 각 프로세스는 독립된 GOT 를 가지고 Process마다 공유 라이브러리 함수의 가상메모리 주소가 다르다.(BaseAddress가 다르므로)
            
    - **.rel.* / .rela.* section**
        
        재배치 과정에서 링커가 활용할 정보 ⇒ 
        
         1.**재배치가 적용**되야하는 **특정 주소**
        
         2.**해당 주소에 연결되야하**는 **특정 값을 참조** 하는 방법 
        
        ```bash
        Section Headers:
        Type : 현재 Section의 유형 정보
        ES : sh_entsize(현재 section table의 각 entry의 크기)
        Flg : sh_flags(섹션의 추가정보 : **쓰기(W)/메모리 적재(A)/실행 가능 명령어(X)**)
        Lk : sh_link(각 Section사이의 연관 관계 정보)
        Inf : sh_info(Section과 관련된 추가 정보)
        Al : sh_addralign(메모리 접근 효율성을 위한 배수값)
        [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
        [**10] .rela.dyn         RELA            00000000004004b0 0004b0 000030 18   A  6   0  8
        # 메모리 정렬 8바이트, .dynsym과 관련, 메모리 적재(A), Entry Size = 18
        [11] .rela.plt         RELA            00000000004004e0 0004e0 000018 18  AI  6  24  8
        # 메모리 정렬 8바이트, .dynsym과 관련, .got.plt에 추가 정보, Entry Size = 18**
        
        **$ readelf --relocs a.out**
        ; Object 파일이 아니므로 **모두 동적 링크 정보**만 남아있다.
        
        Relocation section '.rela.dyn' at offset 0x4b0 contains 2 entries:
          Offset          Info           Type           Sym. Value    Sym. Name + Addend
        **000000403ff0**  **000100000006 R_X86_64_GLOB_DAT 0000000000000000 __libc_start_main@GLIBC_2.34 + 0**
        **000000403ff8**  **000300000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ + 0
        $ objdump -M intel -j .got -d out_not_strip**     
        
        out_not_strip:     file format elf64-x86-64
        
        Disassembly of section .got:
        
        0000000000403ff0 <.got>:
        	... **#데이터 심벌의 주소 계산, .got의 올바른 오프셋 연결
        ; .got의 주소 영역 => Shared Library Symbol data 재배치 처리**
        
        Relocation section '.rela.plt' at offset 0x4e0 contains 1 entry:
          Offset          Info           Type           Sym. Value    Sym. Name + Addend
        **000000404018**  **000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
        $ objdump -M intel -j .got.plt -d out_not_strip**     
        
        out_not_strip:     file format elf64-x86-64
        
        Disassembly of section .got.plt:
        
        0000000000404000 <_GLOBAL_OFFSET_TABLE_>:
          404000:	20 3e 40 00 00 00 00 00 00 00 00 00 00 00 00 00      >@.............
        	...
          **404018:	30 10 40 00 00 00 00 00** #여기는 동적 재배치 되어야함     0.@.....
        **; .got.plt 주소 영역 => Shared Library Function 재배치 처리**
        ```
        
        **R_X86_64_GLOB_DAT : Shared Library Symbol Data의 주소를 계산하고 .got의 올바른 오프셋과 연결**
        
        **R_X86_64_JUMP_SLO : Jump Slot 이라 부르며 Shared Library의 함수의 주소를 담을수있는 슬롯**
        
    - **.dynamic section**
        
        **ELF 바이너리가 실행**될때 **운영체제와 동적 링커**에게 **road map**제시
        
        버전 의존성 정보, 의존하는 라이브러리 정보, 동적 문자열 테이블, 동적 심벌 테이블 등
        
        ```bash
        Section Headers:
        Type : 현재 Section의 유형 정보
        ES : sh_entsize(현재 section table의 각 entry의 크기)
        Flg : sh_flags(섹션의 추가정보 : **쓰기(W)/메모리 적재(A)/실행 가능 명령어(X)**)
        Lk : sh_link(각 Section사이의 연관 관계 정보)
        Inf : sh_info(Section과 관련된 추가 정보)
        Al : sh_addralign(메모리 접근 효율성을 위한 배수값)
        [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
        **[22] .dynamic          DYNAMIC         0000000000403e20 002e20 0001d0 10  WA  7   0  8
        # 메모리 정렬 8바이트, 메모리 쓰기(W), 메모리 적재(A), .dynstr 관련 Entry Size = 10**
        **$ readelf --dynamic a.out** 
        
        Dynamic section at offset 0x2e20 contains 24 entries:
          Tag                Type                Name/Value
        ** 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]**
         0x000000000000000c (INIT)               0x401000
         0x000000000000000d (FINI)               0x401160
         0x0000000000000019 (INIT_ARRAY)         0x403e10
         0x000000000000001b (INIT_ARRAYSZ)       8 (bytes)
         0x000000000000001a (FINI_ARRAY)         0x403e18
         0x000000000000001c (FINI_ARRAYSZ)       8 (bytes)
         0x000000006ffffef5 (GNU_HASH)           0x4003b0
         0x0000000000000005 (STRTAB)             0x400430
         0x0000000000000006 (SYMTAB)             0x4003d0
         0x000000000000000a (STRSZ)              72 (bytes)
         0x000000000000000b (SYMENT)             24 (bytes)
         0x0000000000000015 (DEBUG)              0x0
         0x0000000000000003 (PLTGOT)             0x404000
         0x0000000000000002 (PLTRELSZ)           24 (bytes)
         0x0000000000000014 (PLTREL)             RELA
         0x0000000000000017 (JMPREL)             0x4004e0
         0x0000000000000007 (RELA)               0x4004b0
         0x0000000000000008 (RELASZ)             48 (bytes)
         0x0000000000000009 (RELAENT)            24 (bytes)
         **0x000000006ffffffe (VERNEED)            0x400480**
         **0x000000006fffffff (VERNEEDNUM)         1**
         0x000000006ffffff0 (VERSYM)             0x400478
         0x0000000000000000 (NULL)               0x0
        ```
        
        **DT_NEEDED : 현재 바이너리 파일과의 의존성 정보(즉, 현재 바이너리 파일은 libc.so.6 파일이 필요함)**
        
        **DT_VERNEED : 버전 의존성 테이블의 시작주소**
        
        **DT_VERNEEDNUM : 버전 의존성 테이블의 엔트리 수**
        
    - **.init_array / .fini_array section**
        
        main함수가 시작되기 전에 호출된다.
        
        ``__**attribute__**((constructor))를 이용해 C 소스 파일의 함수를 생성자로 지정가능`
        
        .init_array : 생성자 함수들을 연결하는 포인터 배열
        
        .fini_array : 소멸자 함수들을 연결하는 포인터 배열
        
        ```bash
        Section Headers:
        Type : 현재 Section의 유형 정보
        ES : sh_entsize(현재 section table의 각 entry의 크기)
        Flg : sh_flags(섹션의 추가정보 : **쓰기(W)/메모리 적재(A)/실행 가능 명령어(X)**)
        Lk : sh_link(각 Section사이의 연관 관계 정보)
        Inf : sh_info(Section과 관련된 추가 정보)
        Al : sh_addralign(메모리 접근 효율성을 위한 배수값)
        [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
        [**20] .init_array       INIT_ARRAY      0000000000403e10 002e10 000008 08  WA  0   0  8
        [21] .fini_array       FINI_ARRAY      0000000000403e18 002e18 000008 08  WA  0   0  8**
        
        **$ objdump -d --section .init_array a.out** 
        
        a.out:     file format elf64-x86-64
        
        Disassembly of section .init_array:
        
        0000000000403e10 <__frame_dummy_init_array_entry>:
          403e10:	**30 11 40 00 00 00 00 00**                             0.@.....
        
        **$ objdump -d a.out | grep frame_dummy
        0000000000401130** **<frame_dummy>:**
        ```
        
        현재 .init_array는 frame_dummy함수를 가리키고있다.
        
        - .init_array와 .fini_array에 포함된 포인터는 변경하기 쉬우므로 초기화/종료 작업에서 일부 코드를 바이너리에 추가해 후킹 기능을 삽입하기 좋은 위치이다.
    - **.shstrab / .symtab / .strtab / .dynsym / .dynstr section**
        - **.shstratab section : 모든 section들의 이름을 저장**
            
            ```bash
            Section Headers:
            Type : 현재 Section의 유형 정보
            ES : sh_entsize(현재 section table의 각 entry의 크기)
            Flg : sh_flags(섹션의 추가정보 : **쓰기(W)/메모리 적재(A)/실행 가능 명령어(X)**)
            Lk : sh_link(각 Section사이의 연관 관계 정보)
            Inf : sh_info(Section과 관련된 추가 정보)
            Al : sh_addralign(메모리 접근 효율성을 위한 배수값)
            [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
            **[30] .shstrtab         STRTAB          0000000000000000 003533 00011f 00      0   0  1
            # 메모리 정렬 1바이트**
            **$ readelf -x .shstrtab a.out** 
            
            Hex dump of section '.shstrtab':
              0x00000000 002e7379 6d746162 002e7374 72746162 ..symtab..strtab
              0x00000010 002e7368 73747274 6162002e 696e7465 ..shstrtab..inte
              0x00000020 7270002e 6e6f7465 2e676e75 2e70726f rp..note.gnu.pro
              0x00000030 70657274 79002e6e 6f74652e 676e752e perty..note.gnu.
              0x00000040 6275696c 642d6964 002e6e6f 74652e41 build-id..note.A
              0x00000050 42492d74 6167002e 676e752e 68617368 BI-tag..gnu.hash
              0x00000060 002e6479 6e73796d 002e6479 6e737472 ..dynsym..dynstr
              0x00000070 002e676e 752e7665 7273696f 6e002e67 ..gnu.version..g
              0x00000080 6e752e76 65727369 6f6e5f72 002e7265 nu.version_r..re
              0x00000090 6c612e64 796e002e 72656c61 2e706c74 la.dyn..rela.plt
              0x000000a0 002e696e 6974002e 706c742e 73656300 ..init..plt.sec.
              0x000000b0 2e746578 74002e66 696e6900 2e726f64 .text..fini..rod
              0x000000c0 61746100 2e65685f 6672616d 655f6864 ata..eh_frame_hd
              0x000000d0 72002e65 685f6672 616d6500 2e696e69 r..eh_frame..ini
              0x000000e0 745f6172 72617900 2e66696e 695f6172 t_array..fini_ar
              0x000000f0 72617900 2e64796e 616d6963 002e676f ray..dynamic..go
              0x00000100 74002e67 6f742e70 6c74002e 64617461 t..got.plt..data
              0x00000110 002e6273 73002e63 6f6d6d65 6e7400   ..bss..comment.
            ```
            
        
        아래의 .symtab, strtab는 **모두 정적 링킹**시 사용되므로 만약 바이너리가 strip된다면 모두 없어진다.
        
        ---
        
        - **.strtab section : symbol들의 실제이름**
            
            ```bash
            Section Headers:
            Type : 현재 Section의 유형 정보
            ES : sh_entsize(현재 section table의 각 entry의 크기)
            Flg : sh_flags(섹션의 추가정보 : **쓰기(W)/메모리 적재(A)/실행 가능 명령어(X)**)
            Lk : sh_link(각 Section사이의 연관 관계 정보)
            Inf : sh_info(Section과 관련된 추가 정보)
            Al : sh_addralign(메모리 접근 효율성을 위한 배수값)
            [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
            **[29] .strtab           STRTAB          0000000000000000 003390 0001a3 00      0   0  1**
            
            **$ readelf -x .strtab a.out**
            
            Hex dump of section '.strtab':
              0x00000000 00637274 312e6f00 5f5f6162 695f7461 .crt1.o.__abi_ta
              0x00000010 67006372 74737475 66662e63 00646572 g.crtstuff.c.der
              0x00000020 65676973 7465725f 746d5f63 6c6f6e65 egister_tm_clone
              0x00000030 73005f5f 646f5f67 6c6f6261 6c5f6474 s.__do_global_dt
              0x00000040 6f72735f 61757800 636f6d70 6c657465 ors_aux.complete
              0x00000050 642e3000 5f5f646f 5f676c6f 62616c5f d.0.__do_global_
              0x00000060 64746f72 735f6175 785f6669 6e695f61 dtors_aux_fini_a
              0x00000070 72726179 5f656e74 72790066 72616d65 rray_entry.frame
              0x00000080 5f64756d 6d79005f 5f667261 6d655f64 _dummy.__frame_d
              0x00000090 756d6d79 5f696e69 745f6172 7261795f ummy_init_array_
              0x000000a0 656e7472 7900636f 6d70696c 6174696f entry.compilatio
              0x000000b0 6e5f6578 616d706c 652e6300 5f5f4652 n_example.c.__FR
              0x000000c0 414d455f 454e445f 5f005f44 594e414d AME_END__._DYNAM
              0x000000d0 4943005f 5f474e55 5f45485f 4652414d IC.__GNU_EH_FRAM
              0x000000e0 455f4844 52005f47 4c4f4241 4c5f4f46 E_HDR._GLOBAL_OF
              0x000000f0 46534554 5f544142 4c455f00 5f5f6c69 FSET_TABLE_.__li
              0x00000100 62635f73 74617274 5f6d6169 6e40474c bc_start_main@GL
              0x00000110 4942435f 322e3334 00707574 7340474c IBC_2.34.puts@GL
              0x00000120 4942435f 322e322e 35005f65 64617461 IBC_2.2.5._edata
              0x00000130 005f6669 6e69005f 5f646174 615f7374 ._fini.__data_st
              0x00000140 61727400 5f5f676d 6f6e5f73 74617274 art.__gmon_start
              0x00000150 5f5f005f 5f64736f 5f68616e 646c6500 __.__dso_handle.
              0x00000160 5f494f5f 73746469 6e5f7573 6564005f _IO_stdin_used._
              0x00000170 656e6400 5f646c5f 72656c6f 63617465 end._dl_relocate
              0x00000180 5f737461 7469635f 70696500 5f5f6273 _static_pie.__bs
              0x00000190 735f7374 61727400 6d61696e 005f5f54 s_start.main.__T
              0x000001a0 4d435f45 4e445f5f 005f696e 697400   MC_END__._init.
            ```
            
        - **.symtab section : symbol table의 정보 : 코드 / 데이터 : 함수 / 변수명**
            
            ```bash
            Section Headers:
            Type : 현재 Section의 유형 정보
            ES : sh_entsize(현재 section table의 각 entry의 크기)
            Flg : sh_flags(섹션의 추가정보 : **쓰기(W)/메모리 적재(A)/실행 가능 명령어(X)**)
            Lk : sh_link(각 Section사이의 연관 관계 정보)
            Inf : sh_info(Section과 관련된 추가 정보)
            Al : sh_addralign(메모리 접근 효율성을 위한 배수값)
            [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
            [28] .symtab           **SYMTAB**          0000000000000000 003058 000330 18     29  18  8
            **# 메모리 정렬 8바이트, .eh_frame_hdr 추가 정보, .strtab와 관련**
            												 ; **정적 링킹**을 위한 Symbol Data
            [29] .strtab           STRTAB          0000000000000000 003388 0001af 00      0   0  1
            
            **$ readelf -s .symtab a.out** 
            readelf: Error: '.symtab': No such file
            
            File: a.out
            
            Symbol table '.symtab' contains 34 entries:
               Num:    Value          Size Type    Bind   Vis      Ndx Name
                 0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
                 1: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crt1.o
                 2: 000000000040038c    32 OBJECT  LOCAL  DEFAULT    4 __abi_tag
                 3: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
                 4: 0000000000401090     0 FUNC    LOCAL  DEFAULT   15 deregister_tm_clones
                 5: 00000000004010c0     0 FUNC    LOCAL  DEFAULT   15 register_tm_clones
                 6: 0000000000401100     0 FUNC    LOCAL  DEFAULT   15 __do_global_dtors_aux
                 7: 0000000000404030     1 OBJECT  LOCAL  DEFAULT   26 completed.0
                 8: 0000000000403e18     0 OBJECT  LOCAL  DEFAULT   21 __do_global_dtor[...]
                 9: 0000000000401130     0 FUNC    LOCAL  DEFAULT   15 frame_dummy
                10: 0000000000403e10     0 OBJECT  LOCAL  DEFAULT   20 __frame_dummy_in[...]
                11: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS compilation_example.c
                12: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
                13: 00000000004020e8     0 OBJECT  LOCAL  DEFAULT   19 __FRAME_END__
                14: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS 
                15: 0000000000403e20     0 OBJECT  LOCAL  DEFAULT   22 _DYNAMIC
                16: 0000000000402014     0 NOTYPE  LOCAL  DEFAULT   18 __GNU_EH_FRAME_HDR
                17: 0000000000404000     0 OBJECT  LOCAL  DEFAULT   24 _GLOBAL_OFFSET_TABLE_
                18: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_mai[...]
                19: 0000000000404020     0 NOTYPE  WEAK   DEFAULT   25 data_start
                20: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5
                21: 0000000000404030     0 NOTYPE  GLOBAL DEFAULT   25 _edata
                22: 0000000000401160     0 FUNC    GLOBAL HIDDEN    16 _fini
                23: 0000000000404020     0 NOTYPE  GLOBAL DEFAULT   25 __data_start
                24: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
                25: 0000000000404028     0 OBJECT  GLOBAL HIDDEN    25 __dso_handle
                26: 0000000000402000     4 OBJECT  GLOBAL DEFAULT   17 _IO_stdin_used
                27: 0000000000404038     0 NOTYPE  GLOBAL DEFAULT   26 _end
                28: 0000000000401080     5 FUNC    GLOBAL HIDDEN    15 _dl_relocate_sta[...]
                29: 0000000000401050    38 FUNC    GLOBAL DEFAULT   15 _start
                30: 0000000000404030     0 NOTYPE  GLOBAL DEFAULT   26 __bss_start
                31: 0000000000401136    41 FUNC    GLOBAL DEFAULT   15 main
                32: 0000000000404030     0 OBJECT  GLOBAL HIDDEN    25 __TMC_END__
                33: 0000000000401000     0 FUNC    GLOBAL HIDDEN    12 _init
            ```
            
        
        아래의 section은 **동적 링킹 단계**에서의 symbol, string 정보를 담고있다. 따라서 strip 될 수 없다!
        
        ---
        
        - **.dynsym Section, .dynstr Section**
            
            ```bash
            Section Headers:
            Type : 현재 Section의 유형 정보
            ES : sh_entsize(현재 section table의 각 entry의 크기)
            Flg : sh_flags(섹션의 추가정보 : **쓰기(W)/메모리 적재(A)/실행 가능 명령어(X)**)
            Lk : sh_link(각 Section사이의 연관 관계 정보)
            Inf : sh_info(Section과 관련된 추가 정보)
            Al : sh_addralign(메모리 접근 효율성을 위한 배수값)
            [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
            [ 6] .dynsym           **DYNSYM**          00000000004003d0 0003d0 000060 18   A  7   1  8
            											   ; **동적 링킹**을 위한 Symbol Data(데이터/주소)
            **# 메모리 정렬 8바이트, .interp 추가정보, .dynstr와 관련, 메모리 적재(A)**
            [ 7] .dynstr           STRTAB          0000000000400430 000430 000048 00   A  0   0  1
            												 ; **동적 링킹**을 위한 실제 Symbol의 String
            **#  메모리 정렬 없음**
            **$ readelf --dyn-syms a.out** 
            
            Symbol table '.dynsym' contains 4 entries:
               Num:    Value          Size Type    Bind   Vis      Ndx Name
                 0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
                 1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND _[...]@GLIBC_2.34 (2)
                 2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (3)
                 3: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
            
            **$ readelf -x .dynstr a.out**
            
            Hex dump of section '.dynstr':
              0x00400430 005f5f6c 6962635f 73746172 745f6d61 .__libc_start_ma
              0x00400440 696e0070 75747300 6c696263 2e736f2e in.puts.libc.so.
              0x00400450 3600474c 4942435f 322e322e 3500474c 6.GLIBC_2.2.5.GL
              0x00400460 4942435f 322e3334 005f5f67 6d6f6e5f IBC_2.34.__gmon_
              0x00400470 73746172 745f5f00                   start__.
            ```
            

---

- **3. Program Header table(Optional)**
    
    모든 프로그램은 **Process로 Memory에 적재**되며, 이때 **모든 Section은 Segment라는 단일 조각으로 묶여서 Memory에 적재**된다. Segment의 개념은 **실행가능한 바이너리에서만 적용**되며, **재배치가능한 Object파일에서는 적용되지 않는다.**
    
    ```c
    typedef struct
    {
      Elf64_Word	p_type;			/* Segment type */
      Elf64_Word	p_flags;		/* Segment flags */
      Elf64_Off	p_offset;		/* Segment file offset */
      Elf64_Addr	p_vaddr;		/* Segment virtual address */
      Elf64_Addr	p_paddr;		/* Segment physical address */
      Elf64_Xword	p_filesz;		/* Segment size in file */
      Elf64_Xword	p_memsz;		/* Segment size in memory */
      Elf64_Xword	p_align;		/* Segment alignment */
    } Elf64_Phdr;
    ```
    

- **Program Header table을 참고한 분석**
    
    ```bash
    **[-l|--program-headers|--segments]**
    
    **$ readelf --segments --wide a.out**
    
    Elf file type is EXEC (Executable file)
    Entry point 0x401050
    There are 13 program headers, starting at offset 64
    
    Program Headers:
    index  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
    	0		 **PHDR**           0x000040 0x0000000000400040 0x0000000000400040 0x0002d8 0x0002d8 R   0x8
    	1		 **INTERP**         0x000318 0x0000000000400318 0x0000000000400318 0x00001c 0x00001c R   0x1
    				      **[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]**
    	2		 **LOAD**           0x000000 0x0000000000400000 0x0000000000400000 0x0004f8 0x0004f8 **R**   0x1000
    	3		 **LOAD**           0x001000 0x0000000000401000 0x0000000000401000 0x00016d 0x00016d **R E** 0x1000
    	4		 **LOAD**           0x002000 0x0000000000402000 0x0000000000402000 0x0000ec 0x0000ec **R**   0x1000
    	5		 **LOAD**           0x002e10 0x0000000000403e10 0x0000000000403e10 0x000220 0x000228 **RW**  0x1000
    	6		 **DYNAMIC**        0x002e20 0x0000000000403e20 0x0000000000403e20 0x0001d0 0x0001d0 RW  0x8
    	7		 NOTE           0x000338 0x0000000000400338 0x0000000000400338 0x000030 0x000030 R   0x8
    	8		 NOTE           0x000368 0x0000000000400368 0x0000000000400368 0x000044 0x000044 R   0x4
    	9		 GNU_PROPERTY   0x000338 0x0000000000400338 0x0000000000400338 0x000030 0x000030 R   0x8
    	10   GNU_EH_FRAME   0x002014 0x0000000000402014 0x0000000000402014 0x000034 0x000034 R   0x4
    	11	 GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10
    	12	 GNU_RELRO      0x002e10 0x0000000000403e10 0x0000000000403e10 0x0001f0 0x0001f0 R   0x1
    
     **Section to Segment mapping:
      Segment Sections...
       00     
       01     .interp 
       02     .interp .note.gnu.property .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt 
       03     .init .plt .plt.sec .text .fini 
       04     .rodata .eh_frame_hdr .eh_frame 
       05     .init_array .fini_array .dynamic .got .got.plt .data .bss 
       06     .dynamic 
       07     .note.gnu.property 
       08     .note.gnu.build-id .note.ABI-tag 
       09     .note.gnu.property 
       10     .eh_frame_hdr 
       11     
       12     .init_array .fini_array .dynamic .got
    
    Section과 Segment를 매핑한 결과 => Segment는 결국 여러개의 Section이 모인 것**
    ```
    
    - **p_type**
    
    세그먼트의 유형을 정의
    
    **PT_LOAD : Process가 초기 생성되고 메모리에 로드되는 과정에서 사용, 적어도 두개의 Segment가 Load되는데, 한개는 쓰기가 불가능한 Section, 한개는 쓰기가 가능한 Section**
    
    **PT_DYNAMIC** : **.dynamic Section이 포함**되어있고, 바이너리가 실행될때, **인터프리터가 수행** 해야할 구문 분석등의 **준비작업**
    
    **PT_INTERP : 바이너리가 로드될때 사용할 인터프리터의 이름 지정**
    
    **PT_PHDR : 프로그램 헤더 테이블을 구성**
    
    - **p_flags**
    
    세그먼트에 대한 runtime 접근 권한
    
    **PF_X** : 해당 세그먼트에 대해 항상 실행 권한 부여, **코드 세그먼트를 위해 사용(E)**
    
    **PF_W** : 해당 세그먼트에 기록이 가능, 쓰기 가능한 데이터 세그먼트를 위해 사용, **코드 세그먼트에는 절대로 사용하지 않는다.**
    
    PF_R : 읽기 전용 세그먼트, 데이터,코드 세그먼트에 상관없이 모두 사용
    
    - **p_offset, p_vaddr, p_paddr, p_filesz, p_memsz**
    - p_offset : 세그먼트의 시작 지점 파일 오프셋
    - p_vaddr : 세그먼트의 로드될 가상 메모리 주소
    
    → **p_offset값과, p_vaddr값은 반드시 일치**해야하며 **페이지 크기(일반적으로 4096바이트)(p_align)(2의 거듭제곱)의 배수 관계**여야 한다.
    
    일부 시스템에서 사용 ⇒ p_paddr : 세그먼트의 로드될 물리 메모리 주소 그러나 현대 리눅스를 비롯한 운영체제는 이를 불허하며 0으로 설정한다. **모든 바이너리**는 **가상메모리에 로드**된다.
    
    - p_filesz : 파일에서 세그먼트의 사이즈
    - p_memsz는 세그먼트의 메모리에서의 크기
    
    p_filesz와 p_memsz값이 따로 존재 하는 이유
    
    file에서 존재할때와 메모리에서 존재할때의 크기가 다를 수 있다. 왜냐하면 .bss Section의 경우 디스크에 존재 할때에는 아직 초기화 되지 않은 변수이고, 모두 0으로 초기화 되므로 디스크 공간을 절약하기 위해 저장되지 않는다. 그러나 .bss Section이 Segment로 메모리에 적재될때에는 아무리 0이더라도 메모리에 적재되어야한다. 따라서 p_filesz ≤ p_memsz와 같은 경우가생길 수 있으므로 별도의 값으로 구별한다.
    
    - **p_align**
    
    세그먼트의 정렬에 필요한 바이트의 크기이다. 0 또는 1인경우 정렬이 필요하지 않고 
    
    만약 다른 값인 경우 반드시 **2의 거듭제곱** && **p_vaddr is equal p_offset && p_align과 배수관계**
    

---

- **연습 문제**
    - **수동으로 헤더 검사하기**
        
        > xxd 명령을 이용해 ELF File Header를 분석
        > 
        
        ```bash
        **$ xxd a.out** 
        00000000: **7f45 4c46** **0201 0100 0000 0000 0000 0000**  **.ELF**............
        00000010: 0200 3e00 0100 0000 5010 4000 0000 0000  ..>.....P.@.....
        00000020: 4000 0000 0000 0000 5836 0000 0000 0000  @.......X6......
        00000030: 0000 0000 4000 3800 0d00 4000 1f00 1e00  ....@.8...@.....
        ```
        
        **0x7f, 0x45, 0x4c, 0x46 : e_ident 배열의 Magic Code**
        
        **0x02 : EI_CLASS 64bit**
        
        **0x01 : EI_DATA little endian**
        
        **0x01 : EI_VESION current**
        
        **0x00 : EI_OSABI UNIX System V ABI**
        
        **0x00 : EI_ABIVERSION Default**
        
        **7바이트 0x00 : EI_PADDING**
        
        ![Untitled 3](https://user-images.githubusercontent.com/104804087/224589447-cd00301a-12df-4558-a58e-d0716a672319.png)
        0x0002 : ET_EXEC 실행가능한 바이너리 파일
        
        ![Untitled 4](https://user-images.githubusercontent.com/104804087/224589462-acc90f55-6aa4-4742-a0e4-500a393808b6.png)
        0x003e : EM_X86_64
        
        ![Untitled 5](https://user-images.githubusercontent.com/104804087/224589485-b85cbe54-9467-48d9-874c-c2effaa1cbf0.png)

        0x00000001 : EV_CURRENT
        
        0x00000000 00401050 : entry Point (_start함수의 주소)
        
        0x00000000 00000040 : 프로그램 헤더 테이블 파일 오프셋
        
        0x00000000 00003658 : Section Header Table의 파일 오프셋
        
        0x00000000 : 아키텍쳐 정보 x86_64 인텔 → 0
        
        0x0040 : e_ehsize ELF File Header의 크기
        
        0x0038 : program Header의 크기
        
        0x000d : program Header의 개수
        
        0x0040 : Section Header의 크기
        
        0x001f : Section Header table의 개수
        
        0x001e : .shstrtab Section Header의 인덱스
        
    - **섹션과 세그먼트**
        
        > readelf 명령어를 이용해 ELF 바이너리의 Section과 Segment의 정보를 확인하고 각각의 Section들은 어떻게 Segment와 매핑되는지 확인. 바이너리가 디스크에 있을때와 메모리에적재 됐을때의 상관관계 분석
        > 
        
        ```bash
        Disassembly of section .plt.sec:
        
        0000000000401040 <puts@plt>:
          401040:	f3 0f 1e fa          	endbr64 
          401044:	f2 ff 25 cd 2f 00 00 	bnd jmp QWORD PTR [rip+0x2fcd]        # 404018 <puts@GLIBC_2.2.5>
          40104b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
        ```
        
        objdump 결과에서는 puts@plt의 점프문은 0x404018를 가리키고 있지만 실행시
        
        ![Untitled 6](https://user-images.githubusercontent.com/104804087/224589516-9762f641-ee7e-447f-8c43-6788dfeb49c0.png)
        
        0x00401030을 따라가면 401020(.plt Section)에서 어떤값을 push하고 
        
        ![Untitled 7](https://user-images.githubusercontent.com/104804087/224589543-ee66b0f4-a56f-4b67-800a-e4b5481ed054.png)
        
        동적링커를 호출해 pust함수의 주소를 매핑한다.
        
        ![Untitled 8](https://user-images.githubusercontent.com/104804087/224589576-b4d2f9a6-961d-4b8f-ac56-ed972b21fa82.png)
       
        ..중간에 jmp 명령어 생략
        
        ![Untitled 9](https://user-images.githubusercontent.com/104804087/224589593-4d9e7cdb-ae9e-4e1c-8ac4-bb68cab763ae.png)
        
    - **C와 C++ 바이너리**
        
        > readelf 명령어를 이용해 C, C++ 바이너리를 각각 분석
        > 
        - C++ 파일
            
            ```cpp
            #include <iostream>
            
            using namespace std;
            
            int main() {
                cout << "Hello World!\n" << endl;
                return 0;
            }
            ```
            
            ```bash
            **$ g++ -lstdc++ -std=c++17 b.cpp -o b.out**
            
            **$ readelf -h b.out** 
            ELF Header:
              Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
              Class:                             ELF64
              Data:                              2's complement, little endian
              Version:                           1 (current)
              OS/ABI:                            UNIX - System V
              ABI Version:                       0
              **Type:                              DYN (Position-Independent Executable file)**
              Machine:                           Advanced Micro Devices X86-64
              Version:                           0x1
              Entry point address:               0x10c0
              Start of program headers:          64 (bytes into file)
              Start of section headers:          14528 (bytes into file)
              Flags:                             0x0
              Size of this header:               64 (bytes)
              Size of program headers:           56 (bytes)
              Number of program headers:         13
              Size of section headers:           64 (bytes)
              Number of section headers:         31
              Section header string table index: 30
            ```
            
            PIE(Position Independent Executables)는 강화된 패키지 빌드 프로세스의 출력. PIE 바이너리와 모든 종속성은 애플리케이션이 실행될 때마다 가상 메모리 내의 임의의 위치에 로드. 따라서 Return Oriented Programming (ROP) 공격을 안정적으로 실행하기가 훨씬 더 어려워 진다.
            
    - **지연 바인딩**
        
        > objdump 명령어를 이용해 ELF 바이너리의 PLT Section을 DisAssemble하고 PLT 구문이 사용하는 GOT 항목은? objdump명령어를 이용해 GOT 항목의 내용을 확인하고 PLT와의 관계를 분석
        >
