# 5장 리눅스 바이너리 분석 기초(CTF 문제)

```
리눅스 바이너리 분석 기초(CTF 문제)**
├── file : 파일 확장자에 속지 않고 고유한 magic bytes를 이용해 파일의 형식 분석
├── head : 파일의 처음 부분의 일부를 확인
├── base64 : base64로 인코딩 또는 디코딩
├── ldd : 라이브러리의 종속성 문제를 확인(주의 : 실제로 프로그램을 실행함)
├── grep : 파일의 텍스트를 찾음
├── xxd : 바이너리 파일을 hex로 출력
├── dd : 파일의 일부분을 추출해서 새로 만듦
├── readelf : ELF파일의 헤더와 Segment Header, Program Header를 읽음
├── c++filt : c++언어의 name mangling을 원래의 이름으로 복구
├── nm : c++언어의 name mangling을 원래의 이름으로 복구
├── strings : 바이너리 파일 내부에 있는 모든 문자열을 출력
├── strace : 바이너리가 호출한 모든 system call의 정보를 출력**
├── ltrace : 바이너리가 호출한 모든 Library Function의 call 정보를 출력
├── objdump : 바이너리 정적 분석 도구
└── gdb : 바이너리 동적 분석 도구**
```

- 이 장의 목표
    
    CTF(Capture The Flag)방식으로 기본 문제를 풀며 리눅스 바이너리 분석 도구를 익히고 바이너리 분석 의 이해도와 실력을 높인다.
    
- 사용한 도구 총정리
    
    ```bash
    $ file # 파일의 확장자에 속지않고 고유한 magic bytes를 이용해 파일의 형식 분석
    $ head # plain text의 내용을 일부 확인
    $ base64 # base64로 인코딩 또는 디코딩한다.
    $ ldd # 라이브러리의 종속성 문제를 확인한다.(주의: 실제로 프로그램을 실행함)
    $ grep # 파일의 텍스트를 찾는다.
    $ xxd # 바이너리 파일을 hex로 출력한다.
    $ dd # 파일의 일부분을 추출해서 새로 만든다.
    $ readelf # ELF파일의 헤더와 Segment Header, Program Header를 읽는다.
    $ c++filt # c++언어의 name mangling을 원래의 이름으로 복구한다.
    $ nm      # c++언어의 name mangling을 원래의 이름으로 복구한다.
    $ strings # 바이너리 파일 내부에 있는 모든 문자열을 출력한다.
    $ strace # 바이너리가 호출한 모든 system call의 정보를 출력한다.
    $ ltrace # 바이너리가 호출한 모든 Library Function의 Call 정보를 출력한다.
    $ objdump # 대표적인 바이너리의 정적 분석도구
    $ gdb # 리눅스의 대표적인 바이너리 동적 분석 및 디버깅 도구 
    ```
    

```bash
**$ ls -al # 현재 주어진 payload파일이 무엇을 수행하는지 알 수 없다.**
-rw-rw-r-- 1 dong dong 8633 10월 23 15:43 payload
```

- 따라서 **file 명령어**로 현재파일의 형식을 분석한다.
    
    **file 명령어**는 **파일의 확장자 형식에 속지 않고** 파일의 **고유한 magic bytes를 이용**한다.(예를 들어 **ELF파일**의 경우에는 **0x7f 라는 고유한 코드** 존재) 
    
    ```bash
    **$ file payload**
    payload: ASCII text
    ```
    
- file 명령어로 확인 **ASCII text 임을 확인** 했으므로 payload의 **plain text 내용을 head 명령어로 확인**한다.
    
    head 명령어는 텍스트 파일의 10줄까지 출력한다.
    
    ```bash
    **$ head payload**
    H4sIABzY61gAA+xaD3RTVZq/Sf+lFJIof1r+2aenKKh0klJKi4MmJaUvWrTSFlgR0jRN20iadpKX
    UljXgROKjbUOKuOfWWfFnTlzZs/ZXTln9nTRcTHYERhnZ5c/R2RGV1lFTAFH/DNYoZD9vvvubd57
    bcBl1ln3bL6e9Hvf9+733e/+v+/en0dqId80WYAWLVqI3LpooUXJgUpKFy6yEOsCy6KSRQtLLQsW
    EExdWkIEyzceGVA4JLmDgkCaA92XTXel9/9H6ftVNcv0Ot2orCe3E5RiJhuVbUw/fH3SxkbKSS78
    v47MJtkgZynS2YhNxYeZa84NLF0G/DLhV66X5XK9TcVnsXSc6xQ8S1UCm4o/M5moOCHCqB3Geny2
    rD0+u1HFD7I4junVdnpmN8zshll6zglPr1eXL5P96pm+npWLcwdL51CkR6r9UGrGZ8O1zN+1NhUv
    ZelKNXb3gl02+fpkZnwFyy9VvQgsfs55O3zH72sqK/2Ov3m+3xcId8/vLi+bX1ZaHOooLqExmVna
    6rsbaHpejwKLeQqR+wC+n/ePA3n/duKu2kNvL175+MxD7z75W8GC76aSZLv1xgSdkGnLRV0+/KbD
    7+UPnnhwadWbZ459b/Wsl/o/NZ468olxo3P9wOXK3Qe/a8fRmwhvcTVdl0J/UDe+nzMp9M4U+n9J
    oX8jhT5HP77+ZIr0JWT8+NvI+OnvTpG+NoV/Qwr9Vyn0b6bQkxTl+ixF+p+m0N+qx743k+wWGlX6
    ```
    
    출력 결과는 **영어 알파벳 대소문자와 / + 기호가 혼합**되어있고 **한줄씩 정확하게 끊어져 있다**. 일반적으로 이런 형식으로 저장되어 있다면 **Base64 방식으로 인코딩** 되어있다고 생각해도 된다.
    
- head 명령어로 plain text를 보고 형식이 **Base64 형식과 흡사**하므로 **base64 명령어를 이용해 현재 파일을 디코딩** 한다.
    
    ```bash
    **-d, --decode decode data
    $ base64 -d payload > decoded_payload
    $ ls**
    -rw-rw-r-- 1 dong dong 6390 10월 23 19:18 **decoded_payload**
    -rw-rw-r-- 1 dong dong 8633 10월 23 15:43 payload
    ```
    
- **디코딩된 파일을 다시 file 명령어로 검사**한다.
    
    ```bash
    **$ file decoded_payload** 
    decoded_payload: gzip compressed data, 
    last modified: Mon Apr 10 19:08:12 2017, from Unix, 
    original size modulo 2^32 808960
    ```
    
- **gzip으로 압축된 파일**임을 알았으므로 **file 명령어에서 -z 옵션**으로 **압축파일의 내부파일의 형식을 확인** 할 수 있다.
    
    ```bash
    **-z, --uncompress Try to look inside compressed files.
    $ file -z decoded_payload**
    decoded_payload: POSIX tar archive (GNU) (gzip compressed data, 
    last modified: Mon Apr 10 19:08:12 2017, from Unix)
    ```
    
    gzip 파일안에 tar 파일로 또 압축되어있음
    
- **gzip 파일안에 tar 파일로 압축** 되어 있으므로 **tar zxvf 옵션으로 압축 해제**한다.
    
    ```bash
    **$ tar xvfz decoded_payload** 
    ctf
    67b8601
    ```
    
- **압축 해제된 두개의 파일**을 다시 **file 명령어로 어떤 파일인지 확인**한다.
    
    ```bash
    **$ file ctf**                
    ctf: **ELF 64-bit LSB executable**, x86-64, version 1 (SYSV), 
    dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, 
    for GNU/Linux 2.6.32, 
    BuildID[sha1]=29aeb60bcee44b50d1db3a56911bd1de93cd2030, **stripped**
    
    **$ file 67b8601** 
    67b8601: PC **bitmap**, Windows 3.x format, 512 x 512 x 24, 
    image size 786434, resolution 7872 x 7872 px/m, 
    1165950976 important colors, cbSize 786488, bits offset 54
    ```
    
    **ctf 파일**은 **ELF 64bit 형식으로 실행가능한 파일**이고
    
    **67b8601파일**은 **bitmap 형식의 이미지 파일**임을 알았다.
    
- 실제 분석에서는 파일을 무턱대고 실행하면 안된다.! 
문제를 풀기위해 ctf 파일을 실행한다.
    
    ```bash
    **$ ./ctf** 
    ./ctf: error while loading shared libraries: **lib5ae9b7f.so**: 
    cannot open shared object file: No such file or directory
    ```
    
    동적 라이브러리를 로딩하는데 오류가 생겼다.
    
- **lib5ae9b7f라는 이름은 표준 라이브러리가 아님을 예상**한다. 이 라이브러리를 찾기 전에 **다른 라이브러리의 종속성 문제는 없는지 확인**하고자 **ldd 도구**를 사용한다.
    
    ldd는 라이브러리의 종속성 문제를 확인하기 위해 해당 파일을 실행하므로 가상환경 등 단절된 환경이 아니면 실행해서는 안된다.
    
    ```bash
    **v, --verbose
    Print all information, including, for example, 
    symbol versioning information.
    $ ldd ctf**
    	linux-vdso.so.1 (0x00007ffd75dba000)
    	**lib5ae9b7f.so => not found**
    	libstdc++.so.6 => /lib/x86_64-linux-gnu/libstdc++.so.6 (0x00007f7cbc6cb000)
    	libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007f7cbc6ab000)
    	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7cbc483000)
    	libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f7cbc39c000)
    	/lib64/ld-linux-x86-64.so.2 (0x00007f7cbc908000)
    ```
    
    **lib5ae9b7f.so** 라이브러리 말고는 모두 정상적으로 로드했다.
    
- 라이브러리의 이름을 보고는 도저히 찾을 수 없다. 따라서 문제에서 주어진 파일을 이용한다. **라이브러리 파일도 ELF 형식**을 가진다. 따라서 주어진 파일을 **grep 명령어로 ‘ELF’ 텍스트가 포함되어 있는지 확인**한다.
    
    ```bash
    **$ grep -r "ELF" .**
    grep: ./ctf: 바이너리 파일 일치함
    grep: ./67b8601: 바이너리 파일 일치함
    ```
    
    67b8601파일은 bitmap 파일인줄 알았는데 ELF 텍스트가 포함되어 있다.
    
- **67b8601파일은 bitmap**이지만 **ELF 텍스트가 포함**되는것을 보아 **표준을 따르고 있지 않으**므로 **바이트 단위로 분석**해야한다. 이를위해 **xxd 명령어**를 사용한다.
    
    [**수동으로 헤더 검사하기**](https://www.notion.so/d156792736304c16826a2c27480b65f4)의 형식을 보면 0x7f 0x45 0x4c 0x46 로 시작한다.
    
    ```bash
    **$ xxd 67b8601 | head -n 15**
    00000000: 424d 3800 0c00 0000 0000 3600 0000 2800  BM8.......6...(.
    00000010: 0000 0002 0000 0002 0000 0100 1800 0000  ................
    00000020: 0000 0200 0c00 c01e 0000 c01e 0000 0000  ................
    00000030: 0000 0000 **7f45 4c46 0201 0100 0000 0000  .....ELF........**
    00000040: **0000 0000 0300 3e00 0100 0000 7009 0000  ......>.....p...**
    00000050: **0000 0000 4000 0000 0000 0000 7821 0000  ....@.......x!..**
    00000060: **0000 0000 0000 0000 4000 3800 0700 4000  ........@.8...@.**
    00000070: **1b00 1a00 0100 0000 0500 0000 0000 0000  ................**
    00000080: **0000 0000 0000 0000 0000 0000 0000 0000  ................**
    00000090: **0000 0000 f40e 0000 0000 0000 f40e 0000  ................**
    000000a0: **0000 0000 0000 2000 0000 0000 0100 0000  ...... .........**
    000000b0: **0600 0000 f01d 0000 0000 0000 f01d 2000  .............. .**
    000000c0: **0000 0000 f01d 2000 0000 0000 6802 0000  ...... .....h...**
    000000d0: **0000 0000 7002 0000 0000 0000 0000 2000  ....p......... .**
    000000e0: **0000 0000 0200 0000 0600 0000 081e 0000  ................**
    ```
    
    34번 offset부터 정확하진 않지만 elf헤더임을 확인 할 수 있다.
    
- ELF 헤더임을 추측하고 ctf 파일은 ELF 64 bits 이므로 Shared Library 또한 ELF 64 bits이므로 ELF 헤더의 64바이트 이므로 이를 **dd명령어로 추출**한다.
    
    ```bash
    **$ dd skip=52 count=64 if=67b8601 of=elf_header bs=1**
    64+0 레코드 들어옴
    64+0 레코드 나감
    64 bytes copied, 0.000566536 s, 113 kB/s
    **$ ls**
    67b8601  ctf  decoded_payload  **elf_header**  payload
    **$ xxd elf_header** 
    00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
    00000010: 0300 3e00 0100 0000 7009 0000 0000 0000  ..>.....p.......
    00000020: 4000 0000 0000 0000 7821 0000 0000 0000  @.......x!......
    00000030: 0000 0000 4000 3800 0700 4000 1b00 1a00  ....@.8...@.....
    ```
    
    다시 xxd 명령어로 확인결과 얼쭈 맞는거 같다.
    
- ELF 파일이 잘 분리 되었다고 생각하고 readelf 명령어로 elf header를 분석한다.
    
    ```bash
    **$ readelf -h elf_header**
    ELF Header:
      Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
      Class:                             **ELF64**
      Data:                              **2's complement, little endian**
      Version:                           **1 (current)**
      OS/ABI:                            **UNIX - System V**
      ABI Version:                       **0**
    **readelf: Error: Too many program headers - 0x7 - the file is not that big**
      Type:                              **DYN (Shared object file)**
      Machine:                           Advanced Micro Devices X86-64
      Version:                           0x1
      Entry point address:               0x970
      Start of program headers:          64 (bytes into file)
      Start of section headers:          **8568 (bytes into file)**
      Flags:                             0x0
      Size of this header:               64 (bytes)
      Size of program headers:           56 (bytes)
      Number of program headers:         7
      Size of section headers:           **64 (bytes)**
      Number of section headers:         **27**
      Section header string table index: 26
    **readelf: Error: Reading 1728 bytes extends past end of file for section headers
    readelf: Error: Too many program headers - 0x7 - the file is not that big**
    ```
    
    현재 다른 부분은 모두 잘렸으므로 더이상 읽지 못한다는 오류가 발생한다.
    
- ELF파일의 마지막 부분은 **“일반적으로” Section Header Table이 마지막에 위치**한다.
    
    따라서 다음과 같은 계산식을 유도할 수 있다.
    
    **전체 파일 크기 : Start Of Section Header Table Address + Number of Section Headers * Size Of Section Headers**
    
    8568 + 64 * 27 = 10296 바이트의 크기를 가졌음을 알 수 있다.
    
- 전체 파일의 크기를 예측 했다. 따라서 dd 명령으로 전체 ELF 파일을 예측해서 Shared Library를추출한다.
    
    ```bash
    **$ dd skip=52 count=10296 if=67b8601 of=lib5ae9b7f.so bs=1**
    10296+0 레코드 들어옴
    10296+0 레코드 나감
    10296 bytes (10 kB, 10 KiB) copied, 0.0256981 s, 401 kB/s
    
    **$ ls**
    67b8601  ctf  decoded_payload  elf_header  **lib5ae9b7f.so**  payload
    ```
    
- 추출한 Shared Library를 readelf 명령을 이용해 분석한다.
    
    ```bash
    **[-h|--file-header]
    [-s|--syms|--symbols]**
    **$ readelf -hs lib5ae9b7f.so**
    ELF Header:
      Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
      Class:                             ELF64
      Data:                              2's complement, little endian
      Version:                           1 (current)
      OS/ABI:                            UNIX - System V
      ABI Version:                       0
      Type:                              DYN (Shared object file)
      Machine:                           Advanced Micro Devices X86-64
      Version:                           0x1
      Entry point address:               0x970
      Start of program headers:          64 (bytes into file)
      Start of section headers:          8568 (bytes into file)
      Flags:                             0x0
      Size of this header:               64 (bytes)
      Size of program headers:           56 (bytes)
      Number of program headers:         7
      Size of section headers:           64 (bytes)
      Number of section headers:         27
      Section header string table index: 26
    
    Symbol table '.dynsym' contains 22 entries:
       Num:    Value          Size Type    Bind   Vis      Ndx Name
         0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
         1: 00000000000008c0     0 SECTION LOCAL  DEFAULT    9 .init
         2: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
         3: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _Jv_RegisterClasses
         4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBCXX_3.4.21 (2)
         5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBC_2.2.5 (3)
         6: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterT[...]
         7: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMC[...]
         8: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND [...]@GLIBC_2.2.5 (3)
         9: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __[...]@GLIBC_2.4 (4)
        10: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND [...]@GLIBCXX_3.4 (5)
        11: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND memcpy@GLIBC_2.14 (6)
        **12: 0000000000000bc0   149 FUNC    GLOBAL DEFAULT   12 _Z11rc4_encryptP[...]
        13: 0000000000000cb0   112 FUNC    GLOBAL DEFAULT   12 _Z8rc4_initP11rc[...]**
        14: 0000000000202060     0 NOTYPE  GLOBAL DEFAULT   24 _end
        15: 0000000000202058     0 NOTYPE  GLOBAL DEFAULT   23 _edata
        **16: 0000000000000b40   119 FUNC    GLOBAL DEFAULT   12 _Z11rc4_encryptP[...]
        17: 0000000000000c60     5 FUNC    GLOBAL DEFAULT   12 _Z11rc4_decryptP[...]**
        18: 0000000000202058     0 NOTYPE  GLOBAL DEFAULT   24 __bss_start
        19: 00000000000008c0     0 FUNC    GLOBAL DEFAULT    9 _init
        **20: 0000000000000c70    59 FUNC    GLOBAL DEFAULT   12 _Z11rc4_decryptP[...]**
        21: 0000000000000d20     0 FUNC    GLOBAL DEFAULT   13 _fini
    ```
    
    symbol과 ELF Header를 분석한 결과 흥미로은 몇가지 함수들을 발견했다. C++의 **Name mangling**기법으로 함수들의 이름이 섞여있다. C++의 Name mangling은 **원래의 함수이름 + 함수의 매개변수**들을 조합하여 변형한다.
    
- 현재 우리가 추출한 라이브러리의 symbol들이 mangling되어 읽기 힘드므로 **nm 도구를 이용**해 **Symbol들을 분석**한다. 또는 **c++filt 도구를 이용해 이름을 복원**한다.
    
    ```bash
    **$ nm lib5ae9b7f.so** 
    nm: lib5ae9b7f.so: no symbols
    # nm도구는 기본적으로 정적 Symbol을 분석한다. 
    # 그러나 이파일은 striped 있으므로 올바른 Symbol을 분석하지 못한다. 
    **[-D|--dynamic]
    $ nm -D lib5ae9b7f.so**
    w _ITM_deregisterTMCloneTable
                     w _ITM_registerTMCloneTable
                     w _Jv_RegisterClasses
    0000000000000c60 T _Z11rc4_decryptP11rc4_state_tPhi
    0000000000000c70 T _Z11rc4_decryptP11rc4_state_tRNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE
    0000000000000b40 T _Z11rc4_encryptP11rc4_state_tPhi
    0000000000000bc0 T _Z11rc4_encryptP11rc4_state_tRNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE
    0000000000000cb0 T _Z8rc4_initP11rc4_state_tPhi
                     U _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_createERmm@GLIBCXX_3.4.21
                     U _ZSt19__throw_logic_errorPKc@GLIBCXX_3.4
    0000000000202058 B __bss_start
                     w __cxa_finalize@GLIBC_2.2.5
                     w __gmon_start__
                     U __stack_chk_fail@GLIBC_2.4
    0000000000202058 D _edata
    0000000000202060 B _end
    0000000000000d20 T _fini
    00000000000008c0 T _init
                     U malloc@GLIBC_2.2.5
                     U memcpy@GLIBC_2.14
    # 동적 Symbol들을 분석하긴 했지만 아직까지 name mangling되어 있어 해석하기 힘들다.
    **$ nm -D --demangle lib5ae9b7f.so**
    w _ITM_deregisterTMCloneTable
                     w _ITM_registerTMCloneTable
                     w _Jv_RegisterClasses
    0000000000000c60 T **rc4_decrypt**(rc4_state_t*, unsigned char*, int)
    0000000000000c70 T **rc4_decrypt**(rc4_state_t*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&)
    0000000000000b40 T **rc4_encrypt**(rc4_state_t*, unsigned char*, int)
    0000000000000bc0 T **rc4_encrypt**(rc4_state_t*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&)
    0000000000000cb0 T **rc4_init**(rc4_state_t*, unsigned char*, int)
                     U std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_create(unsigned long&, unsigned long)@GLIBCXX_3.4.21
                     U std::__throw_logic_error(char const*)@GLIBCXX_3.4
    0000000000202058 B __bss_start
                     w __cxa_finalize@GLIBC_2.2.5
                     w __gmon_start__
                     U __stack_chk_fail@GLIBC_2.4
    0000000000202058 D _edata
    0000000000202060 B _end
    0000000000000d20 T _fini
    00000000000008c0 T _init
                     U malloc@GLIBC_2.2.5
                     U memcpy@GLIBC_2.14
    **$ c++filt _Z11rc4_decryptP11rc4_state_tPhi**
    rc4_decrypt(rc4_state_t*, unsigned char*, int)
    ```
    
    RC4 암호화를 진행한다.
    
현재까지 진행을 살펴보면 의문의 payload ⇒ decode ⇒ ctf, 67b8601, **67b8601 파일**로부터 **lib5ae9b7f.so** 추출 ⇒ c++filt, nm도구를 통해 name mangling 해제. **lib5ae9b7f.so파일의 대략적인 기능을 살펴봤다.(암호화 및 복호화)**

- Shared Library는 /lib등 다수의 표준 디렉터리들을 탐색한다. 직접 추출한 lib5ae9b7f.so파일은 표준 디렉터리에 위치하지 않으므로 LD_LIBRARY_PATH 환경 변수로 강제 설정 한다.
    
    ```bash
    **$ export LD_LIBRARY_PATH=`pwd`
    $ ./ctf
    $ echo $?
    1
    # ctf 프로그램의 종료 결과가 1이므로 정상적으로 종료 되지 않았고 flag값도 나오지 않았다.**
    ```
    
- 이제 뭔가 입력값을 넣어야 할꺼같은 느낌도 들고 **ctf 바이너리에서 힌트**를 얻고자 **어떠한 문자열이 포함되어있는지를 검사하기위해 strings 명령어를 사용**한다.
    
    ```bash
    **$ strings ctf** 
    **/lib64/ld-linux-x86-64.so.2**
    lib5ae9b7f.so
    **__gmon_start__**
    _Jv_RegisterClasses
    _ITM_deregisterTMCloneTable
    _ITM_registerTMCloneTable
    _Z8rc4_initP11rc4_state_tPhi
    _init
    _Z11rc4_decryptP11rc4_state_tRNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE
    _fini
    libstdc++.so.6
    __gxx_personality_v0
    _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6assignEPKc
    _ZdlPv
    _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_assignERKS4_
    libgcc_s.so.1
    _Unwind_Resume
    libc.so.6
    __printf_chk
    fopen
    puts
    __stack_chk_fail
    fgets
    fseek
    fclose
    getenv
    strcmp
    __libc_start_main
    _edata
    __bss_start
    _end
    GCC_3.0
    CXXABI_1.3
    GLIBCXX_3.4.21
    GLIBCXX_3.4
    GLIBC_2.4
    GLIBC_2.3.4
    GLIBC_2.2.5
    D$ H
    D$PH
    |$@H
    D$PH9
    |$ H
    D$0H9
    |$`H
    t$`H
    |$`H
    D$pH9
    T$ H
    L$ 1
    T$@H
    p I9
    |$@H
    D$PH9
    |$ H
    D$0H9
    |$`H
    T$pH
    AWAVA
    AUATL
    []A\A]A^A_
    **DEBUG: argv[1] = %s**
    **checking '%s'**
    **show_me_the_flag**
    >CMb
    -v@P^:
    **flag = %s**
    **guess again!**
    **It's kinda like Louisiana. Or Dagobah. Dagobah - Where Yoda lives!**
    ;*3$"
    zPLR
    GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.4) 5.4.0 20160609
    .shstrtab
    .interp
    .note.ABI-tag
    .note.gnu.build-id
    .gnu.hash
    .dynsym
    .dynstr
    .gnu.version
    .gnu.version_r
    .rela.dyn
    .rela.plt
    .init
    .plt.got
    .text
    .fini
    .rodata
    .eh_frame_hdr
    .eh_frame
    .gcc_except_table
    .init_array
    .fini_array
    .jcr
    .dynamic
    .got.plt
    .data
    .bss
    .comment
    ```
    
    몇개의 의심스러운 문자열을 찾았다.
    
    1. **/lib64/ld-linux-x86-64.so.2**
    2. **DEBUG: argv[1] = %s**
    3. **checking '%s'**
    4. **show_me_the_flag**
    5. **flag = %s**
    6. **guess again!**
    7. **It's kinda like Louisiana. Or Dagobah. Dagobah - Where Yoda lives!**
    
    1번은 .interp Section에서 발견할수 있는 프로그램의 인터프리터 이름
    
    2번은 프로그램의 커맨드로 들어오는 Argument를 디버깅 하기 위해 적은 문자열임을 알수있다. ⇒ 현재 프로그램은 Argument가 존재한다.
    
    3번은 아마 Argument를 검사하는거 같다.
    
    4번은 뭔가 실제로 동작 할 수도 있을법한 문자열이다.
    
    5번은 뭔가 입력받은 flag(argument)를 출력하는거 같다.
    
    6번,7번은 정확하게 알기 어렵다.
    
- 위의 분석에서 Argument가 필요한거 같으니 임의의 Argument를 입력해 결과를 확인 해보자.
    
    ```bash
    **$ ./ctf foobar**
    checking 'foobar'
    **$ echo $?**
    1
    # foobar는 정확한 값이 아닌듯 함
    # 위에서 발견한 show_me_the_flag값을 넣어본다
    **$ ./ctf show_me_the_flag** 
    checking 'show_me_the_flag'
    ok
    **$ echo $?**
    1
    # 뭔가 작동했다! 그러나 종료 결과값은 1로 아직은 빠뜨린 값이 있는듯하다.
    ```
    
- 이제 프로그램에서 정확히 어떤일이 일어나는지 확인하기 위해 strace 명령어와 ltrace 명령어를 사용한다. 각각 시스템콜과 라이브러리 호출을 파악한다.
    
    ```bash
    **$ strace ./ctf foobar**
    execve("./ctf", ["./ctf", "foobar"], 0x7ffccc4e4578 /* 63 vars */) = 0
    # shell 환경에서 ctf파일을 실행시켜주는 System Call
    brk(NULL)                               = 0x1c86000
    arch_prctl(0x3001 /* ARCH_??? */, 0x7fff69148c10) = -1 EINVAL (부적절한 인수)
    mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f615d2fe000
    access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    # LD_LIBRARY_PATH 값을 `pwd`로 설정했으므로 현재 디렉터리에서 .so파일을 검색한다.
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/glibc-hwcaps/x86-64-v3/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    newfstatat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/glibc-hwcaps/x86-64-v3", 0x7fff69147e30, 0) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/glibc-hwcaps/x86-64-v2/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    newfstatat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/glibc-hwcaps/x86-64-v2", 0x7fff69147e30, 0) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/tls/haswell/x86_64/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    newfstatat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/tls/haswell/x86_64", 0x7fff69147e30, 0) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/tls/haswell/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    newfstatat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/tls/haswell", 0x7fff69147e30, 0) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/tls/x86_64/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    newfstatat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/tls/x86_64", 0x7fff69147e30, 0) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/tls/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    newfstatat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/tls", 0x7fff69147e30, 0) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/haswell/x86_64/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    newfstatat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/haswell/x86_64", 0x7fff69147e30, 0) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/haswell/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    newfstatat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/haswell", 0x7fff69147e30, 0) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/x86_64/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    newfstatat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/x86_64", 0x7fff69147e30, 0) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    **# SystemCall이 하는일을 발견했다! Shared Library파일을 열고
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = 3
    # Shared Library파일을 읽는다.
    read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0p\t\0\0\0\0\0\0"..., 832) = 832
    # 파일의 정보를 가져온다.
    newfstatat(3, "", {st_mode=S_IFREG|0664, st_size=10296, ...}, AT_EMPTY_PATH) = 0
    # Shared Library파일을 메모리에 매핑한다.
    mmap(NULL, 4202592, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f615cefb000
    mmap(0x7f615d000000, 2105440, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0) = 0x7f615d000000
    # 가상 메모리 주소 공간 매핑 해제
    munmap(0x7f615cefb000, 1069056)         = 0
    munmap(0x7f615d203000, 1024096)         = 0
    # 메모리의 보호를 설정한다.
    mprotect(0x7f615d001000, 2097152, PROT_NONE) = 0
    mmap(0x7f615d201000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1000) = 0x7f615d201000
    # Shared Library파일을 닫는다.
    close(3)                                = 0**
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/libstdc++.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
    newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=68471, ...}, AT_EMPTY_PATH) = 0
    mmap(NULL, 68471, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f615d2ed000
    close(3)                                = 0
    openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libstdc++.so.6", O_RDONLY|O_CLOEXEC) = 3
    read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0\0\0\0\0\0\0\0"..., 832) = 832
    newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=2252096, ...}, AT_EMPTY_PATH) = 0
    mmap(NULL, 2267328, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f615cdd6000
    mmap(0x7f615ce70000, 1114112, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x9a000) = 0x7f615ce70000
    mmap(0x7f615cf80000, 454656, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1aa000) = 0x7f615cf80000
    mmap(0x7f615cfef000, 57344, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x218000) = 0x7f615cfef000
    mmap(0x7f615cffd000, 10432, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f615cffd000
    close(3)                                = 0
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/libgcc_s.so.1", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libgcc_s.so.1", O_RDONLY|O_CLOEXEC) = 3
    read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0\0\0\0\0\0\0\0"..., 832) = 832
    newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=125488, ...}, AT_EMPTY_PATH) = 0
    mmap(NULL, 127720, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f615d2cd000
    mmap(0x7f615d2d0000, 94208, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x3000) = 0x7f615d2d0000
    mmap(0x7f615d2e7000, 16384, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1a000) = 0x7f615d2e7000
    mmap(0x7f615d2eb000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1d000) = 0x7f615d2eb000
    close(3)                                = 0
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
    read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\237\2\0\0\0\0\0"..., 832) = 832
    pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
    pread64(3, "\4\0\0\0 \0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0"..., 48, 848) = 48
    pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0i8\235HZ\227\223\333\350s\360\352,\223\340."..., 68, 896) = 68
    newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=2216304, ...}, AT_EMPTY_PATH) = 0
    pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
    mmap(NULL, 2260560, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f615cbae000
    mmap(0x7f615cbd6000, 1658880, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7f615cbd6000
    mmap(0x7f615cd6b000, 360448, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1bd000) = 0x7f615cd6b000
    mmap(0x7f615cdc3000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x214000) = 0x7f615cdc3000
    mmap(0x7f615cdc9000, 52816, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f615cdc9000
    close(3)                                = 0
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/libm.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libm.so.6", O_RDONLY|O_CLOEXEC) = 3
    read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0\0\0\0\0\0\0\0"..., 832) = 832
    newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=940560, ...}, AT_EMPTY_PATH) = 0
    mmap(NULL, 942344, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f615cac7000
    mmap(0x7f615cad5000, 507904, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0xe000) = 0x7f615cad5000
    mmap(0x7f615cb51000, 372736, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x8a000) = 0x7f615cb51000
    mmap(0x7f615cbac000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0xe4000) = 0x7f615cbac000
    close(3)                                = 0
    mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f615d2cb000
    mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f615d2c8000
    arch_prctl(ARCH_SET_FS, 0x7f615d2c8740) = 0
    set_tid_address(0x7f615d2c8a10)         = 154275
    set_robust_list(0x7f615d2c8a20, 24)     = 0
    rseq(0x7f615d2c90e0, 0x20, 0, 0x53053053) = 0
    mprotect(0x7f615cdc3000, 16384, PROT_READ) = 0
    mprotect(0x7f615cbac000, 4096, PROT_READ) = 0
    mprotect(0x7f615d2eb000, 4096, PROT_READ) = 0
    mprotect(0x7f615cfef000, 45056, PROT_READ) = 0
    mprotect(0x7f615d201000, 4096, PROT_READ) = 0
    mprotect(0x601000, 4096, PROT_READ)     = 0
    mprotect(0x7f615d338000, 8192, PROT_READ) = 0
    prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
    munmap(0x7f615d2ed000, 68471)           = 0
    getrandom("\xc1\x47\x44\x2d\x8d\x6b\x0b\xfd", 8, GRND_NONBLOCK) = 8
    brk(NULL)                               = 0x1c86000
    brk(0x1ca7000)                          = 0x1ca7000
    **# 1번 fd는 stdout
    # 파일의 정보(stdout)를 가져온다.**
    **newfstatat(1, "", {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0x3), ...}, AT_EMPTY_PATH) = 0
    # stdout에 값을 쓴다.
    write(1, "checking 'foobar'\n", 18checking 'foobar'
    )     = 18
    # 프로그램이 종료된 이유 syscall
    exit_group(1)                           = ?**
    +++ exited with 1 +++
    ///////////////////////////
    **$ strace ./ctf show_me_the_flag**
    execve("./ctf", ["./ctf", "show_me_the_flag"], 0x7ffedf7e8d98 /* 63 vars */) = 0
    brk(NULL)                               = 0xee0000
    arch_prctl(0x3001 /* ARCH_??? */, 0x7ffe42f220f0) = -1 EINVAL (부적절한 인수)
    mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f56abc4f000
    access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/glibc-hwcaps/x86-64-v3/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    newfstatat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/glibc-hwcaps/x86-64-v3", 0x7ffe42f21310, 0) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/glibc-hwcaps/x86-64-v2/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    newfstatat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/glibc-hwcaps/x86-64-v2", 0x7ffe42f21310, 0) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/tls/haswell/x86_64/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    newfstatat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/tls/haswell/x86_64", 0x7ffe42f21310, 0) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/tls/haswell/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    newfstatat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/tls/haswell", 0x7ffe42f21310, 0) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/tls/x86_64/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    newfstatat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/tls/x86_64", 0x7ffe42f21310, 0) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/tls/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    newfstatat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/tls", 0x7ffe42f21310, 0) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/haswell/x86_64/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    newfstatat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/haswell/x86_64", 0x7ffe42f21310, 0) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/haswell/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    newfstatat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/haswell", 0x7ffe42f21310, 0) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/x86_64/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    newfstatat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/x86_64", 0x7ffe42f21310, 0) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/lib5ae9b7f.so", O_RDONLY|O_CLOEXEC) = 3
    read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0p\t\0\0\0\0\0\0"..., 832) = 832
    newfstatat(3, "", {st_mode=S_IFREG|0664, st_size=10296, ...}, AT_EMPTY_PATH) = 0
    mmap(NULL, 4202592, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f56ab84c000
    mmap(0x7f56aba00000, 2105440, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0) = 0x7f56aba00000
    munmap(0x7f56ab84c000, 1785856)         = 0
    munmap(0x7f56abc03000, 307296)          = 0
    mprotect(0x7f56aba01000, 2097152, PROT_NONE) = 0
    mmap(0x7f56abc01000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1000) = 0x7f56abc01000
    close(3)                                = 0
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/libstdc++.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
    newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=68471, ...}, AT_EMPTY_PATH) = 0
    mmap(NULL, 68471, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f56abc3e000
    close(3)                                = 0
    openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libstdc++.so.6", O_RDONLY|O_CLOEXEC) = 3
    read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0\0\0\0\0\0\0\0"..., 832) = 832
    newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=2252096, ...}, AT_EMPTY_PATH) = 0
    mmap(NULL, 2267328, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f56ab7d6000
    mmap(0x7f56ab870000, 1114112, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x9a000) = 0x7f56ab870000
    mmap(0x7f56ab980000, 454656, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1aa000) = 0x7f56ab980000
    mmap(0x7f56ab9ef000, 57344, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x218000) = 0x7f56ab9ef000
    mmap(0x7f56ab9fd000, 10432, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f56ab9fd000
    close(3)                                = 0
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/libgcc_s.so.1", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libgcc_s.so.1", O_RDONLY|O_CLOEXEC) = 3
    read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0\0\0\0\0\0\0\0"..., 832) = 832
    newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=125488, ...}, AT_EMPTY_PATH) = 0
    mmap(NULL, 127720, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f56abc1e000
    mmap(0x7f56abc21000, 94208, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x3000) = 0x7f56abc21000
    mmap(0x7f56abc38000, 16384, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1a000) = 0x7f56abc38000
    mmap(0x7f56abc3c000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1d000) = 0x7f56abc3c000
    close(3)                                = 0
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
    read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\237\2\0\0\0\0\0"..., 832) = 832
    pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
    pread64(3, "\4\0\0\0 \0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0"..., 48, 848) = 48
    pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0i8\235HZ\227\223\333\350s\360\352,\223\340."..., 68, 896) = 68
    newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=2216304, ...}, AT_EMPTY_PATH) = 0
    pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
    mmap(NULL, 2260560, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f56ab5ae000
    mmap(0x7f56ab5d6000, 1658880, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7f56ab5d6000
    mmap(0x7f56ab76b000, 360448, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1bd000) = 0x7f56ab76b000
    mmap(0x7f56ab7c3000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x214000) = 0x7f56ab7c3000
    mmap(0x7f56ab7c9000, 52816, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f56ab7c9000
    close(3)                                = 0
    openat(AT_FDCWD, "/home/dongFiles/\353\263\264\354\225\210\352\263\265\353\266\200/BinaryAnalysisStudy/Lecture_5/libm.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (그런 파일이나 디렉터리가 없습니다)
    openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libm.so.6", O_RDONLY|O_CLOEXEC) = 3
    read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0\0\0\0\0\0\0\0"..., 832) = 832
    newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=940560, ...}, AT_EMPTY_PATH) = 0
    mmap(NULL, 942344, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f56ab4c7000
    mmap(0x7f56ab4d5000, 507904, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0xe000) = 0x7f56ab4d5000
    mmap(0x7f56ab551000, 372736, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x8a000) = 0x7f56ab551000
    mmap(0x7f56ab5ac000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0xe4000) = 0x7f56ab5ac000
    close(3)                                = 0
    mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f56abc1c000
    mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f56abc19000
    arch_prctl(ARCH_SET_FS, 0x7f56abc19740) = 0
    set_tid_address(0x7f56abc19a10)         = 173044
    set_robust_list(0x7f56abc19a20, 24)     = 0
    rseq(0x7f56abc1a0e0, 0x20, 0, 0x53053053) = 0
    mprotect(0x7f56ab7c3000, 16384, PROT_READ) = 0
    mprotect(0x7f56ab5ac000, 4096, PROT_READ) = 0
    mprotect(0x7f56abc3c000, 4096, PROT_READ) = 0
    mprotect(0x7f56ab9ef000, 45056, PROT_READ) = 0
    mprotect(0x7f56abc01000, 4096, PROT_READ) = 0
    mprotect(0x601000, 4096, PROT_READ)     = 0
    mprotect(0x7f56abc89000, 8192, PROT_READ) = 0
    prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
    munmap(0x7f56abc3e000, 68471)           = 0
    getrandom("\x22\xf8\x6c\xbd\xb9\x25\x24\xdb", 8, GRND_NONBLOCK) = 8
    brk(NULL)                               = 0xee0000
    brk(0xf01000)                           = 0xf01000
    **newfstatat(1, "", {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0x3), ...}, AT_EMPTY_PATH) = 0
    write(1, "checking 'show_me_the_flag'\n", 28checking 'show_me_the_flag'
    ) = 28
    write(1, "ok\n", 3ok
    )                     = 3**
    exit_group(1)                           = ?
    +++ exited with 1 +++
    ```
    

현재 ctf파일에서 syscall을 관찰하는것은 큰도움은 되지 않았지만 strace로 syscall을 분석하는것은 바이너리 분석뿐만아니라 디버깅 용도로도 매우 중요하다. 

- strace로 syscall을 분석했으니 **ltrace로 라이브러리 호출을 분석**한다.
    
    `rc4_state_t*`: 함수가 사용하는 rc4_state_t 데이터 구조체에 대한 포인터입니다. `0x7ffe10d8fec0`은 메모리에서 이 구조체의 주소입니다.
    `unsigned char*`: 함수가 사용하는 `암호화 키에 대한 포인터`입니다. `0x4011c0`은 메모리에서 이 키의 주소입니다.
    `int`: 키의 길이를 바이트 단위로 지정하는 정수 값입니다. `66은 키의 길이`입니다.
    `void*`: 함수에서 사용되지 않는 일부 데이터에 대한 포인터입니다. `0x7fa366314a37`이 이 인수의 값입니다.
    
    ```bash
    **-i     
    Print the instruction pointer at the time of the library call.
    -C, --demangle
    Decode (demangle) low-level symbol names  into  user-level  names.
    Besides removing any initial underscore prefix used by the system,
    this makes C++ function names readable**
    **$ ltrace -i -C ./ctf show_me_the_flag**
    [0x400fe9] __libc_start_main(0x400bc0, 2, 0x7fff2f1b4e78, 0x4010c0 <unfinished ...>
    [0x400c44] __printf_chk(1, 0x401158, 0x7fff2f1b62e4, 256checking 'show_me_the_flag'
    ) = 28
    [0x400c51] strcmp("show_me_the_flag", "show_me_the_flag") = 0
    [0x400cf0] puts("ok"ok
    )                             = 3
    
    # **0x4011c0주소에 있는 key**로 rc4를 초기화한다.
    [0x400d07] **rc4_init**(rc4_state_t*, unsigned char*, int)
    (**0x7fff2f1b4c10**,   **0x4011c0**, 66,    0x7fe6258c2a37) = 0
    **0x7fff2f1b4c10 : rc4_state_t 구조체**, 
    **0x4011c0 : 암호화 키
    66 :  키길이, 
    0x7fe6258c2a37 : 함수에서 사용하지 않는 일부 데이터에 대한 포인터**
    
    # **0x4011c0주소에 있는 문자열을 assign**하고 **std::basic_string을 반환**한다.
    [0x400d14] std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >
    ::**assign(char const*)**(0x7fff2f1b4b50, **0x40117b**, 58, 3) = **0x7fff2f1b4b50
    0x7fff2f1b4b50** : **string 객체가 할당될 주소
    0x40117b : 객체에 할당할 문자열에 대한 포인터
    58 : 문자열의 길이
    3 : 문자열이 지정된 길이보다 짧은 경우 문자열을 패딩
    0x7fff2f1b4b50 : 0x40117b에 있던 문자열이 string객체로 반환
    
    # 할당한 문자열 String과 구조체로 decrypt를 수행한다. 0x7fff2f1b4bb0(decrypt된 문자열?)**
    [0x400d29] **rc4_decrypt**(rc4_state_t*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&)
    (0x7fff2f1b4bb0, **0x7fff2f1b4c10**, **0x7fff2f1b4b50**, 0x7e889f91) = **0x7fff2f1b4bb0
    0x7fff2f1b4bb0 : 복호화된 문자열 객체 주소
    0x7fff2f1b4c10 : rc4_state_t 구조체
    0x7fff2f1b4b50 : 암호화된 문자열 객체 주소
    0x7e889f91 :** std::allocator<char> >&
    **
    
    # 새로 할당된 문자열 주소 : 0x7fff2f1b4bb0**
    [0x400d36] std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >
    ::**_M_assign**(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)
    (0x7fff2f1b4b50, **0x7fff2f1b4bb0**, **0x7fff2f1b4bc0**, 0) = 0
    **0x7fff2f1b4b50 : 복사할 대상의 버퍼
    0x7fff2f1b4bb0 : 복사할 소스 객체
    0x7fff2f1b4bc0 : 복사할 대상의 버퍼 끝
    0 : 사용되지 않는 정수값**
    
    [0x400d53] **getenv("GUESSME")**                      = nil
    [0xffffffffffffffff] +++ exited (status 1) +++
    ```
    
- GUESSME 환경변수를 확인하는 코드를 발견했으므로 환경변수를 설정 후 프로그램을 실행해보자
    
    ```bash
    **$ GUESSME='foobar' ./ctf show_me_the_flag**
    checking 'show_me_the_flag'
    ok
    guess again!
    **$ echo $?**
    1
    
    **$ GUESSME='foobar' ltrace -i -C ./ctf show_me_the_flag**
    [0x400fe9] __libc_start_main(0x400bc0, 2, 0x7fff00eb9a48, 0x4010c0 <unfinished ...>
    [0x400c44] __printf_chk(1, 0x401158, 0x7fff00ebb2d5, 256checking 'show_me_the_flag'
    ) = 28
    [0x400c51] strcmp("show_me_the_flag", "show_me_the_flag") = 0
    [0x400cf0] puts("ok"ok
    )                             = 3
    
    [0x400d07] rc4_init(rc4_state_t*, unsigned char*, int)
    (0x7fff00eb97e0, 0x4011c0, 66, 0x7f0a3e2c2a37) = 0
    
    [0x400d14] std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >
    ::assign(char const*)(0x7fff00eb9720, 0x40117b, 58, 3) = 0x7fff00eb9720
    
    [0x400d29] rc4_decrypt(rc4_state_t*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&)
    (0x7fff00eb9780, 0x7fff00eb97e0, 0x7fff00eb9720, 0x7e889f91) = 0x7fff00eb9780
    
    [0x400d36] std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >
    ::_M_assign(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)
    (0x7fff00eb9720, 0x7fff00eb9780, 0x7fff00eb9790, 0) = 0
    
    **[0x400d53] getenv("GUESSME")                      = "foobar"**
    
    [0x400d6e] std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >
    ::**assign**(char const*)
    (0x7fff00eb9740, **0x401183**, 5, 224) = **0x7fff00eb9740**
    
    [0x400d88] rc4_decrypt(rc4_state_t*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&)
    (0x7fff00eb97a0, 0x7fff00eb97e0, **0x7fff00eb9740**, 49) = **0x7fff00eb97a0**
    
    [0x400d9a] std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >
    ::**_M_assign**(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)
    (0x7fff00eb9740, **0x7fff00eb97a0**, **0x18c2330**, 0) = 0
    #/////여기서 어떠한 작업이 일어나고 판단을 한다.////#
    [0x400db4] operator delete(void*)(0x18c2330, 0x18c2330, 21, 0) = 0
    
    [0x400dd7] puts("guess again!"guess again!
    )                   = 13
    
    [0x400c8d] operator delete(void*)(0x18c22e0, 1, 1, 0x7f0a3e2c2a37) = 0
    
    [0xffffffffffffffff] +++ exited (status 1) +++
    
    ```
    
- 판단이 일어나는 부분은 별도의 라이브러리를 이용하지않고 확인하므로 ltrace 도구로는 알 수 없으므로 **어셈블리 분석을 실행**한다. ⇒ **objdump를 이용**한다.
    
    “guess again!” 문자열이 어디서 나타나는지 확인하기위해 .rodata를 확인한다.
    
    ```bash
    **-s
    --full-contents
    Display the full contents of any sections requested.  
    By default all non-empty sections are displayed.
    [-j section|--section=section]
    $ objdump -s --section .rodata ctf**
    
    ctf:     file format elf64-x86-64
    
    Contents of section .rodata:
     401140 01000200 44454255 473a2061 7267765b  ....DEBUG: argv[
     401150 315d203d 20257300 63686563 6b696e67  1] = %s.checking
     401160 20272573 270a0073 686f775f 6d655f74   '%s'..show_me_t
     401170 68655f66 6c616700 6f6b004f 89df919f  he_flag.ok.O....
     401180 887e009a 5b38babe 27ac0e3e 434d6285  .~..[8..'..>CMb.
     401190 55868954 3848a34d 00192d76 40505e3a  U..T8H.M..-v@P^:
     4011a0 00726200 666c6167 203d2025 730a00**67**  .rb.flag = %s..**g**
     4011b0 **75657373 20616761 696e2100** 00000000  **uess again!.**....
     4011c0 49742773 206b696e 6461206c 696b6520  It's kinda like 
     4011d0 4c6f7569 7369616e 612e204f 72204461  Louisiana. Or Da
     4011e0 676f6261 682e2044 61676f62 6168202d  gobah. Dagobah -
     4011f0 20576865 72652059 6f646120 6c697665   Where Yoda live
     401200 73210000 00000000                    s!......
    ```
    
    guess again! 문자열은 **0x4011af**에 존재한다.
    
- puts함수와 “guess agian!” 가 나타나는곳 근처를 objdump로 disassemble한다.
    
    **C언어의 전형적인 반복문 형태 외워!**
    
    ```bash
    **$ objdump -d -M intel ctf**
      **400dc0:	0f b6 14 03          	movzx  edx,BYTE PTR [rbx+rax*1]
    																				; rbx=>baseAddr, rax=>Index**
      400dc4:	84 d2                	test   dl, dl
      **400dc6:	74 05                	je     400dcd <__gmon_start__@plt+0x21d>
    																				; 마지막이 NULL이면 guess again!으로 간다.**
      400dc8:	3a 14 01             	cmp    dl,**BYTE PTR** [rcx+rax*1] 
    																				; rcx=>baseAddr, rax=>Index
      400dcb:	74 13                	je     **400de0** <__gmon_start__@plt+0x230>
      **400dcd:	bf af 11 40 00**       	**mov    edi,0x4011af ; "guess again!"**
      400dd2:	e8 d9 fc ff ff       	**call   400ab0 <puts@plt>**
      400dd7:	e9 84 fe ff ff       	jmp    400c60 <__gmon_start__@plt+0xb0>
      400ddc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
      **400de0:	48 83 c0 01          	add    rax,0x1**
      400de4:	48 83 f8 15          	cmp    rax,0x15
    																				;만약 0x15개 모두 BYTE PTR[rcx + rax*1]과 같다면 
    																	; equal되므로 더이상 jmp를 하지 않고 아래의 명령어를 실행한다.
      400de8:	75 d6                	jne    **400dc0** <__gmon_start__@plt+0x210>
      400dea:	48 8d 7c 24 40       	lea    rdi,[rsp+0x40]
      400def:	be 99 11 40 00       	mov    esi,0x401199
      400df4:	e8 47 fd ff ff       	call   400b40 <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6assignEPKc@plt>
      400df9:	48 8d 54 24 40       	lea    rdx,[rsp+0x40]
      400dfe:	48 8d b4 24 c0 00 00 	lea    rsi,[rsp+0xc0]
    ```
    
- 현재까지의 정적 분석방법으로는 rcx레지스터값을 알 수가 없다.따라서 동적분석의 대표적인 도구인 gdb를 이용 rcx레지스터의 값을 알아낸다.
    
    ```bash
    **$ export LD_LIBRARY_PATH=`pwd`
    $ gdb ctf** 
    GNU gdb (Ubuntu 12.0.90-0ubuntu1) 12.0.90
    Copyright (C) 2022 Free Software Foundation, Inc.
    License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.
    Type "show copying" and "show warranty" for details.
    This GDB was configured as "x86_64-linux-gnu".
    Type "show configuration" for configuration details.
    For bug reporting instructions, please see:
    <https://www.gnu.org/software/gdb/bugs/>.
    Find the GDB manual and other documentation resources online at:
        <http://www.gnu.org/software/gdb/documentation/>.
    
    For help, type "help".
    Type "apropos word" to search for commands related to "word"...
    Reading symbols from ctf...
    (No debugging symbols found in ctf)
    **(gdb) set disassembly-flavor intel #명령어 표현방법을 intel로 설정함**
    **(gdb) b *0x400dc8 #objdump 결과물에서 cmp 하는 주소에 breakpoint**
    Breakpoint 1 at 0x400dc8
    **(gdb) set env GUESSME=foobar # gdb에서 환경변수 설정**
    **(gdb) run show_me_the_flag # Command Line Argument와 함께 실행**
    Starting program: /home/dongFiles/보안공부/BinaryAnalysisStudy/Lecture_5/ctf show_me_the_flag
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
    checking 'show_me_the_flag'
    ok
    
    Breakpoint 1, 0x0000000000400dc8 in ?? ()
    **(gdb) display/i $pc # 다음 명령어를 출력**
    1: x/i $pc
    => 0x400dc8:	cmp    dl,BYTE PTR [rcx+rax*1]
    **(gdb) display/i $rip # 다음 명령어를 출력**
    1: x/i $rip
    => 0x400dc8:	cmp    dl,BYTE PTR [rcx+rax*1]
    **(gdb) disas 0x400dc0,0x400de8 # 현재 함수의 스코프를 gdb는 파악하지 못해서 disas로 자동으로
    # disassemble 하지 못했으므로 범위를 명시적으로 지정하여 disassemble 한다.**
    Dump of assembler code from 0x400dc0 to 0x400de8:
       0x0000000000400dc0:	movzx  edx,BYTE PTR [rbx+rax*1]
       0x0000000000400dc4:	test   dl,dl
       0x0000000000400dc6:	je     0x400dcd
    => 0x0000000000400dc8:	cmp    dl,BYTE PTR [rcx+rax*1]
       0x0000000000400dcb:	je     0x400de0
       0x0000000000400dcd:	mov    edi,0x4011af
       0x0000000000400dd2:	call   0x400ab0 <puts@plt>
       0x0000000000400dd7:	jmp    0x400c60
       0x0000000000400ddc:	nop    DWORD PTR [rax+0x0]
       0x0000000000400de0:	add    rax,0x1
       0x0000000000400de4:	cmp    rax,0x15
    End of assembler dump.
    **(gdb) info registers $rcx #rcx레지스터의 정보를 가져온다.
    rcx            0x6152e0            6378208**
    **(gdb) x/s 0x6152e0**
    **0x6152e0:	"Crackers Don't Matter" # 정답!**
    ```
    

```bash
**$ GUESSME="Crackers Don't Matter" ./ctf show_me_the_flag**
checking 'show_me_the_flag'
ok
**flag = 84b34c124b2ba5ca224af8e33b077e9e**
```

**연습문제 중요!**

[5장 CTF 연습문제](https://www.notion.so/5-CTF-1f431cbda088406ba39e3553e2daef4e)
