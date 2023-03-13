# 1장. 바이너리란 무엇인가

```
**바이너리란 무엇인가**
├── **C 언어로 작성된 프로그램의 컴파일 과정**
│   ├── 소스 코드
│   ├── 전처리 단계
│   ├── 컴파일 단계
│   ├── 어셈블 단계
│   └── 링킹 단계
├── **심벌과 스트립 바이너리**
│   ├── 심벌 정보 확인
│   └── 바이너리 스트립: 관련 정보 은닉
├── **바이너리 디스어셈블**
│   ├── 목적 파일 디스어셈블 및 참조 의존성 해결방법
│   └── 단독으로 실행 가능한 바이너리 파일 분석
├── **바이너리 로딩과 실행**
|   ├── 인터프리터와 지연바인딩
|   └── elf/PE format의 존재이유
└── **연습 문제**
    ├── 함수의 위치 찾기
    └── 섹션 정보
```

- **C언어로 작성된 프로그램의 컴파일 과정**
    
   <img width="833" alt="Untitled" src="https://user-images.githubusercontent.com/104804087/224695401-1ea7507b-4fff-4806-bc72-206a2d44bf45.png">
   
    - **소스 코드**
        
        ```cpp
        #include <stdio.h>
        
        #define FORMAT_STRING "%s"
        #define MESSAGE "Hello, world!\n"
        
        int main() {
            printf(FORMAT_STRING, MESSAGE);
            return 0;
        }
        ```
        
    - **전처리 단계**
        
        #include, #define의 명령어를 모두 처리함으로써 순수하게 컴파일할 C언어 코드만을 남겨둔다.
        
        header파일을 모두 읽어 들이고, #define을 모두 치환한다.
        
        ```bash
        **$ gcc -E -P compile.c > compile_pre.c
        $ ls**
        compile.c  compile_pre.c
        **$ cat compile_pre.c**
        ```
        
        - compile_pre.c
            
            ```cpp
            typedef long unsigned int size_t;
            typedef __builtin_va_list __gnuc_va_list;
            typedef unsigned char __u_char;
            typedef unsigned short int __u_short;
            typedef unsigned int __u_int;
            typedef unsigned long int __u_long;
            typedef signed char __int8_t;
            typedef unsigned char __uint8_t;
            typedef signed short int __int16_t;
            typedef unsigned short int __uint16_t;
            typedef signed int __int32_t;
            typedef unsigned int __uint32_t;
            typedef signed long int __int64_t;
            typedef unsigned long int __uint64_t;
            typedef __int8_t __int_least8_t;
            typedef __uint8_t __uint_least8_t;
            typedef __int16_t __int_least16_t;
            typedef __uint16_t __uint_least16_t;
            typedef __int32_t __int_least32_t;
            typedef __uint32_t __uint_least32_t;
            typedef __int64_t __int_least64_t;
            typedef __uint64_t __uint_least64_t;
            typedef long int __quad_t;
            typedef unsigned long int __u_quad_t;
            typedef long int __intmax_t;
            typedef unsigned long int __uintmax_t;
            typedef unsigned long int __dev_t;
            typedef unsigned int __uid_t;
            typedef unsigned int __gid_t;
            typedef unsigned long int __ino_t;
            typedef unsigned long int __ino64_t;
            typedef unsigned int __mode_t;
            typedef unsigned long int __nlink_t;
            typedef long int __off_t;
            typedef long int __off64_t;
            typedef int __pid_t;
            typedef struct { int __val[2]; } __fsid_t;
            typedef long int __clock_t;
            typedef unsigned long int __rlim_t;
            typedef unsigned long int __rlim64_t;
            typedef unsigned int __id_t;
            typedef long int __time_t;
            typedef unsigned int __useconds_t;
            typedef long int __suseconds_t;
            typedef long int __suseconds64_t;
            typedef int __daddr_t;
            typedef int __key_t;
            typedef int __clockid_t;
            typedef void * __timer_t;
            typedef long int __blksize_t;
            typedef long int __blkcnt_t;
            typedef long int __blkcnt64_t;
            typedef unsigned long int __fsblkcnt_t;
            typedef unsigned long int __fsblkcnt64_t;
            typedef unsigned long int __fsfilcnt_t;
            typedef unsigned long int __fsfilcnt64_t;
            typedef long int __fsword_t;
            typedef long int __ssize_t;
            typedef long int __syscall_slong_t;
            typedef unsigned long int __syscall_ulong_t;
            typedef __off64_t __loff_t;
            typedef char *__caddr_t;
            typedef long int __intptr_t;
            typedef unsigned int __socklen_t;
            typedef int __sig_atomic_t;
            typedef struct
            {
              int __count;
              union
              {
                unsigned int __wch;
                char __wchb[4];
              } __value;
            } __mbstate_t;
            typedef struct _G_fpos_t
            {
              __off_t __pos;
              __mbstate_t __state;
            } __fpos_t;
            typedef struct _G_fpos64_t
            {
              __off64_t __pos;
              __mbstate_t __state;
            } __fpos64_t;
            struct _IO_FILE;
            typedef struct _IO_FILE __FILE;
            struct _IO_FILE;
            typedef struct _IO_FILE FILE;
            struct _IO_FILE;
            struct _IO_marker;
            struct _IO_codecvt;
            struct _IO_wide_data;
            typedef void _IO_lock_t;
            struct _IO_FILE
            {
              int _flags;
              char *_IO_read_ptr;
              char *_IO_read_end;
              char *_IO_read_base;
              char *_IO_write_base;
              char *_IO_write_ptr;
              char *_IO_write_end;
              char *_IO_buf_base;
              char *_IO_buf_end;
              char *_IO_save_base;
              char *_IO_backup_base;
              char *_IO_save_end;
              struct _IO_marker *_markers;
              struct _IO_FILE *_chain;
              int _fileno;
              int _flags2;
              __off_t _old_offset;
              unsigned short _cur_column;
              signed char _vtable_offset;
              char _shortbuf[1];
              _IO_lock_t *_lock;
              __off64_t _offset;
              struct _IO_codecvt *_codecvt;
              struct _IO_wide_data *_wide_data;
              struct _IO_FILE *_freeres_list;
              void *_freeres_buf;
              size_t __pad5;
              int _mode;
              char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
            };
            typedef __gnuc_va_list va_list;
            typedef __off_t off_t;
            typedef __ssize_t ssize_t;
            typedef __fpos_t fpos_t;
            extern FILE *stdin;
            extern FILE *stdout;
            extern FILE *stderr;
            extern int remove (const char *__filename) __attribute__ ((__nothrow__ , __leaf__));
            extern int rename (const char *__old, const char *__new) __attribute__ ((__nothrow__ , __leaf__));
            extern int renameat (int __oldfd, const char *__old, int __newfd,
                   const char *__new) __attribute__ ((__nothrow__ , __leaf__));
            extern int fclose (FILE *__stream);
            extern FILE *tmpfile (void)
              __attribute__ ((__malloc__)) __attribute__ ((__malloc__ (fclose, 1))) ;
            extern char *tmpnam (char[20]) __attribute__ ((__nothrow__ , __leaf__)) ;
            extern char *tmpnam_r (char __s[20]) __attribute__ ((__nothrow__ , __leaf__)) ;
            extern char *tempnam (const char *__dir, const char *__pfx)
               __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__malloc__)) __attribute__ ((__malloc__ (__builtin_free, 1)));
            extern int fflush (FILE *__stream);
            extern int fflush_unlocked (FILE *__stream);
            extern FILE *fopen (const char *__restrict __filename,
                  const char *__restrict __modes)
              __attribute__ ((__malloc__)) __attribute__ ((__malloc__ (fclose, 1))) ;
            extern FILE *freopen (const char *__restrict __filename,
                    const char *__restrict __modes,
                    FILE *__restrict __stream) ;
            extern FILE *fdopen (int __fd, const char *__modes) __attribute__ ((__nothrow__ , __leaf__))
              __attribute__ ((__malloc__)) __attribute__ ((__malloc__ (fclose, 1))) ;
            extern FILE *fmemopen (void *__s, size_t __len, const char *__modes)
              __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__malloc__)) __attribute__ ((__malloc__ (fclose, 1))) ;
            extern FILE *open_memstream (char **__bufloc, size_t *__sizeloc) __attribute__ ((__nothrow__ , __leaf__))
              __attribute__ ((__malloc__)) __attribute__ ((__malloc__ (fclose, 1))) ;
            extern void setbuf (FILE *__restrict __stream, char *__restrict __buf) __attribute__ ((__nothrow__ , __leaf__));
            extern int setvbuf (FILE *__restrict __stream, char *__restrict __buf,
                  int __modes, size_t __n) __attribute__ ((__nothrow__ , __leaf__));
            extern void setbuffer (FILE *__restrict __stream, char *__restrict __buf,
                     size_t __size) __attribute__ ((__nothrow__ , __leaf__));
            extern void setlinebuf (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__));
            extern int fprintf (FILE *__restrict __stream,
                  const char *__restrict __format, ...);
            extern int printf (const char *__restrict __format, ...);
            extern int sprintf (char *__restrict __s,
                  const char *__restrict __format, ...) __attribute__ ((__nothrow__));
            extern int vfprintf (FILE *__restrict __s, const char *__restrict __format,
                   __gnuc_va_list __arg);
            extern int vprintf (const char *__restrict __format, __gnuc_va_list __arg);
            extern int vsprintf (char *__restrict __s, const char *__restrict __format,
                   __gnuc_va_list __arg) __attribute__ ((__nothrow__));
            extern int snprintf (char *__restrict __s, size_t __maxlen,
                   const char *__restrict __format, ...)
                 __attribute__ ((__nothrow__)) __attribute__ ((__format__ (__printf__, 3, 4)));
            extern int vsnprintf (char *__restrict __s, size_t __maxlen,
                    const char *__restrict __format, __gnuc_va_list __arg)
                 __attribute__ ((__nothrow__)) __attribute__ ((__format__ (__printf__, 3, 0)));
            extern int vdprintf (int __fd, const char *__restrict __fmt,
                   __gnuc_va_list __arg)
                 __attribute__ ((__format__ (__printf__, 2, 0)));
            extern int dprintf (int __fd, const char *__restrict __fmt, ...)
                 __attribute__ ((__format__ (__printf__, 2, 3)));
            extern int fscanf (FILE *__restrict __stream,
                 const char *__restrict __format, ...) ;
            extern int scanf (const char *__restrict __format, ...) ;
            extern int sscanf (const char *__restrict __s,
                 const char *__restrict __format, ...) __attribute__ ((__nothrow__ , __leaf__));
            extern int fscanf (FILE *__restrict __stream, const char *__restrict __format, ...) __asm__ ("" "__isoc99_fscanf") ;
            extern int scanf (const char *__restrict __format, ...) __asm__ ("" "__isoc99_scanf") ;
            extern int sscanf (const char *__restrict __s, const char *__restrict __format, ...) __asm__ ("" "__isoc99_sscanf") __attribute__ ((__nothrow__ , __leaf__));
            extern int vfscanf (FILE *__restrict __s, const char *__restrict __format,
                  __gnuc_va_list __arg)
                 __attribute__ ((__format__ (__scanf__, 2, 0))) ;
            extern int vscanf (const char *__restrict __format, __gnuc_va_list __arg)
                 __attribute__ ((__format__ (__scanf__, 1, 0))) ;
            extern int vsscanf (const char *__restrict __s,
                  const char *__restrict __format, __gnuc_va_list __arg)
                 __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__format__ (__scanf__, 2, 0)));
            extern int vfscanf (FILE *__restrict __s, const char *__restrict __format, __gnuc_va_list __arg) __asm__ ("" "__isoc99_vfscanf")
                 __attribute__ ((__format__ (__scanf__, 2, 0))) ;
            extern int vscanf (const char *__restrict __format, __gnuc_va_list __arg) __asm__ ("" "__isoc99_vscanf")
                 __attribute__ ((__format__ (__scanf__, 1, 0))) ;
            extern int vsscanf (const char *__restrict __s, const char *__restrict __format, __gnuc_va_list __arg) __asm__ ("" "__isoc99_vsscanf") __attribute__ ((__nothrow__ , __leaf__))
                 __attribute__ ((__format__ (__scanf__, 2, 0)));
            extern int fgetc (FILE *__stream);
            extern int getc (FILE *__stream);
            extern int getchar (void);
            extern int getc_unlocked (FILE *__stream);
            extern int getchar_unlocked (void);
            extern int fgetc_unlocked (FILE *__stream);
            extern int fputc (int __c, FILE *__stream);
            extern int putc (int __c, FILE *__stream);
            extern int putchar (int __c);
            extern int fputc_unlocked (int __c, FILE *__stream);
            extern int putc_unlocked (int __c, FILE *__stream);
            extern int putchar_unlocked (int __c);
            extern int getw (FILE *__stream);
            extern int putw (int __w, FILE *__stream);
            extern char *fgets (char *__restrict __s, int __n, FILE *__restrict __stream)
                 __attribute__ ((__access__ (__write_only__, 1, 2)));
            extern __ssize_t __getdelim (char **__restrict __lineptr,
                                         size_t *__restrict __n, int __delimiter,
                                         FILE *__restrict __stream) ;
            extern __ssize_t getdelim (char **__restrict __lineptr,
                                       size_t *__restrict __n, int __delimiter,
                                       FILE *__restrict __stream) ;
            extern __ssize_t getline (char **__restrict __lineptr,
                                      size_t *__restrict __n,
                                      FILE *__restrict __stream) ;
            extern int fputs (const char *__restrict __s, FILE *__restrict __stream);
            extern int puts (const char *__s);
            extern int ungetc (int __c, FILE *__stream);
            extern size_t fread (void *__restrict __ptr, size_t __size,
                   size_t __n, FILE *__restrict __stream) ;
            extern size_t fwrite (const void *__restrict __ptr, size_t __size,
                    size_t __n, FILE *__restrict __s);
            extern size_t fread_unlocked (void *__restrict __ptr, size_t __size,
                     size_t __n, FILE *__restrict __stream) ;
            extern size_t fwrite_unlocked (const void *__restrict __ptr, size_t __size,
                      size_t __n, FILE *__restrict __stream);
            extern int fseek (FILE *__stream, long int __off, int __whence);
            extern long int ftell (FILE *__stream) ;
            extern void rewind (FILE *__stream);
            extern int fseeko (FILE *__stream, __off_t __off, int __whence);
            extern __off_t ftello (FILE *__stream) ;
            extern int fgetpos (FILE *__restrict __stream, fpos_t *__restrict __pos);
            extern int fsetpos (FILE *__stream, const fpos_t *__pos);
            extern void clearerr (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__));
            extern int feof (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;
            extern int ferror (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;
            extern void clearerr_unlocked (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__));
            extern int feof_unlocked (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;
            extern int ferror_unlocked (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;
            extern void perror (const char *__s);
            extern int fileno (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;
            extern int fileno_unlocked (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;
            extern int pclose (FILE *__stream);
            extern FILE *popen (const char *__command, const char *__modes)
              __attribute__ ((__malloc__)) __attribute__ ((__malloc__ (pclose, 1))) ;
            extern char *ctermid (char *__s) __attribute__ ((__nothrow__ , __leaf__))
              __attribute__ ((__access__ (__write_only__, 1)));
            extern void flockfile (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__));
            extern int ftrylockfile (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;
            extern void funlockfile (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__));
            extern int __uflow (FILE *);
            extern int __overflow (FILE *, int);
            
            int main() {
                printf("%s", "Hello, world!\n");
                return 0;
            }
            ```
            
    - **컴파일 단계**
        
        전처리가 끝난 코드는 본격적으로 어셈블리 언어로 변환한다.
        
        ```bash
        **$ gcc -S -masm=intel -no-pie compile.c       
        $ cat compile.s**
        .file	"compile.c"
        	.intel_syntax noprefix
        	.text
        	.section	.rodata
        **.LC0:
        	.string	"Hello, world!"**
        	.text
        	.globl	main
        	.type	main, @function
        **main:**
        .LFB0:
        	.cfi_startproc
        	endbr64
        	push	rbp
        	.cfi_def_cfa_offset 16
        	.cfi_offset 6, -16
        	mov	rbp, rsp
        	.cfi_def_cfa_register 6
        	**lea	rax, .LC0[rip]**
        	mov	rdi, rax
        	call	puts@PLT
        	mov	eax, 0
        	pop	rbp
        	.cfi_def_cfa 7, 8
        	ret
        	.cfi_endproc
        .LFE0:
        	.size	main, .-main
        	.ident	"GCC: (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0"
        	.section	.note.GNU-stack,"",@progbits
        	.section	.note.gnu.property,"a"
        	.align 8
        	.long	1f - 0f
        	.long	4f - 1f
        	.long	5
        0:
        	.string	"GNU"
        1:
        	.align 8
        	.long	0xc0000002
        	.long	3f - 2f
        2:
        	.long	0x3
        3:
        	.align 8
        4:
        ```
        
        **컴파일단계가 끝난 어셈블리언어 파일**은 **symbol 정보가 모두 남아있다.**
        
    - **어셈블 단계**
        
        ```bash
        **$ gcc -c -no-pie compile.c                         
        $ file compile.o**                            
        compile.o: **ELF 64-bit LSB relocatable**, x86-64, version 1 (SYSV), **not stripped**
        ```
        
        재배치 가능한 코드를 생성한다.
        
        컴파일된 assembly 파일들로부터 **object파일은 각자 어셈블링** 되기 때문에, **서로 다른 object파일의 메모리 주소를 참조할 수 있는 방법이 없다.** 따라서 object 파일은 **재배치 가능한 형태로 존재**해야한다.
        
    - **링킹 단계**
        
        ```bash
        **$ gcc -no-pie compile.c -o out_not_strip
        $ file out_not_strip** 
        out_not_strip: **ELF 64-bit LSB executable**, x86-64, version 1 (SYSV), 
        **dynamically linked**, **interpreter /lib64/ld-linux-x86-64.so.2**, 
        BuildID[sha1]=72f735c74da4aa32ea87be682f3b00ef7c104045, 
        for GNU/Linux 3.2.0, **not stripped**
        ```
        
        컴파일의 마지막 단계는 **링킹 단계**이다. 모든 **object파일들을 하나의 실행 가능한 바이너리 형태로 연결**시키는 과정(LTO(Link-Time Optimization 최적화 수행)
        
        **모든 object파일들은 재배치 가능한 속성**을 가지므로 **object파일에 포함된 기호를 참조하여 외부 라이브러리, 내부 함수, 변수등을 모두 연결**한다.
        
        - **ELF 64-bit LSB executable** : ELF 64bit, LSB 숫자 구조, 실행가능한 파일
        - **dynamically linked** : 프로그램에 포함된 라이브러리중 일부가 바이너리에 병합되지 않고 동적 라이브러리를 사용한다.
        - **interpreter /lib64/ld-linux-x86-64.so.2** : 바이너리가 메모리에 로드 될때 동적 라이브러리의 참조 의존성 문제를 해결할때 이 파일을 사용한다.
        - **not stripped** : 바이너리의 기호 정보등이 사라지지 않았다.
- **심벌과 스트립 바이너리**
    
    컴파일러는 symbol을 사용해 각 이름을 처리하고 첫 시작주소, 전체 크기에 대한 정보를 모두 가진다.
    
    - **심벌 정보 확인**
        
        ```bash
        $ readelf --syms out_not_strip 
        
        Symbol table '.dynsym' contains 4 entries:
           Num:    Value          Size Type    Bind   Vis      Ndx Name
             0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
             1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND _[...]@GLIBC_2.34 (2)
             2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (3)
             3: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
        
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
            11: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS compile.c
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
            22: 0000000000401154     0 FUNC    GLOBAL HIDDEN    16 _fini
            23: 0000000000404020     0 NOTYPE  GLOBAL DEFAULT   25 __data_start
            24: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
            25: 0000000000404028     0 OBJECT  GLOBAL HIDDEN    25 __dso_handle
            26: 0000000000402000     4 OBJECT  GLOBAL DEFAULT   17 _IO_stdin_used
            27: 0000000000404038     0 NOTYPE  GLOBAL DEFAULT   26 _end
            28: 0000000000401080     5 FUNC    GLOBAL HIDDEN    15 _dl_relocate_sta[...]
            29: 0000000000401050    38 FUNC    GLOBAL DEFAULT   15 _start
            30: 0000000000404030     0 NOTYPE  GLOBAL DEFAULT   26 __bss_start
            **31: 0000000000401136    30 FUNC    GLOBAL DEFAULT   15 main**
            32: 0000000000404030     0 OBJECT  GLOBAL HIDDEN    25 __TMC_END__
            33: 0000000000401000     0 FUNC    GLOBAL HIDDEN    12 _init
        ```
        
        main 함수의 정보가 나타나있다.
        
    - **바이너리 스트립: 관련 정보 은닉**
        
        현재 컴파일된 바이너리 파일은 strip되지 않은상태이다. 이를 strip해서 관련된 정보를 숨긴다.
        
        ```bash
        **$ strip --strip-all out_not_strip -o out_strip
        $ file out_strip**    
        out_strip: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), 
        dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, 
        BuildID[sha1]=72f735c74da4aa32ea87be682f3b00ef7c104045, 
        for GNU/Linux 3.2.0, **stripped**
        ```
        
- **바이너리 디스어셈블**
    - **목적 파일 디스어셈블 및 참조 의존성 해결방법**
        
        ```bash
        **[-s|--full-contents]
        [-j section|--section=section]
        
        $ objdump -sj .rodata compile.o**    
        
        compile.o:     file format elf64-x86-64
        
        Contents of section .rodata:
         0000 48656c6c 6f2c2077 6f726c64 2100      Hello, world!.
        **$ objdump -M intel -d compile.o**    
        
        compile.o:     file format elf64-x86-64
        
        Disassembly of section .text:
        
        0000000000000000 **<main>:**
           0:	f3 0f 1e fa          	endbr64 
           4:	55                   	push   rbp
           5:	48 89 e5             	mov    rbp,rsp
           8:	48 8d 05 **00 00 00 00** 	lea    rax,[rip+0x0]        # f <main+0xf>
           f:	48 89 c7             	mov    rdi,rax
          12:	e8 **00 00 00 00**       	call   17 <main+0x17>
          17:	b8 00 00 00 00       	mov    eax,0x0
          1c:	5d                   	pop    rbp
          1d:	c3                   	ret
        ```
        
        현재 명령어의 피연산자는 모두 0x00으로 되어있다.
        
        이는 object 파일은 재배치 가능하기 때문인데, 이정보는 relocs 영역에 저장되어있고 이를 링커가 정확한 값으로 치환한다.
        
        ```bash
        **$ readelf --relocs compile.o** 
        
        Relocation section '.rela.text' at offset 0x198 contains 2 entries:
          Offset          Info           Type           Sym. Value    Sym. Name + Addend
        **00000000000b**  000300000002 R_X86_64_PC32     0000000000000000 **.rodata - 4**
        **000000000013**  000500000004 R_X86_64_PLT32    0000000000000000 **puts - 4**
        
        Relocation section '.rela.eh_frame' at offset 0x1c8 contains 1 entry:
          Offset          Info           Type           Sym. Value    Sym. Name + Addend
        000000000020  000200000002 R_X86_64_PC32     0000000000000000 .text + 0
        ```
        
        0x0b 지점에는 .rodata - 4 위치의 값이 참조된다.
        
        0x13 지점에는 puts - 4위치의 값이 참조된다.
        
    - **단독으로 실행 가능한 바이너리 파일 분석**
        - **바이너리가 스트립되지 않았을때**
            
            ```bash
            **$ objdump -M intel -d out_not_strip**
            
            out_not_strip:     file format elf64-x86-64
            
            **Disassembly of section .init:**
            
            0000000000401000 <_init>:
              401000:	f3 0f 1e fa          	endbr64 
              401004:	48 83 ec 08          	sub    rsp,0x8
              401008:	48 8b 05 e9 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fe9]        # 403ff8 <__gmon_start__@Base>
              40100f:	48 85 c0             	test   rax,rax
              401012:	74 02                	je     401016 <_init+0x16>
              401014:	ff d0                	call   rax
              401016:	48 83 c4 08          	add    rsp,0x8
              40101a:	c3                   	ret    
            
            **Disassembly of section .plt:**
            
            0000000000401020 <.plt>:
              401020:	ff 35 e2 2f 00 00    	push   QWORD PTR [rip+0x2fe2]        # 404008 <_GLOBAL_OFFSET_TABLE_+0x8>
              401026:	f2 ff 25 e3 2f 00 00 	bnd jmp QWORD PTR [rip+0x2fe3]        # 404010 <_GLOBAL_OFFSET_TABLE_+0x10>
              40102d:	0f 1f 00             	nop    DWORD PTR [rax]
              401030:	f3 0f 1e fa          	endbr64 
              401034:	68 00 00 00 00       	push   0x0
              401039:	f2 e9 e1 ff ff ff    	bnd jmp 401020 <_init+0x20>
              40103f:	90                   	nop
            
            Disassembly of section .plt.sec:
            
            0000000000401040 <puts@plt>:
              401040:	f3 0f 1e fa          	endbr64 
              401044:	f2 ff 25 cd 2f 00 00 	bnd jmp QWORD PTR [rip+0x2fcd]        # 404018 <puts@GLIBC_2.2.5>
              40104b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
            
            **Disassembly of section .text:**
            
            0000000000401050 <_start>:
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
              401068:	48 c7 c7 36 11 40 00 	mov    rdi,0x401136
              40106f:	ff 15 7b 2f 00 00    	call   QWORD PTR [rip+0x2f7b]        # 403ff0 <__libc_start_main@GLIBC_2.34>
              401075:	f4                   	hlt    
              401076:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
              40107d:	00 00 00 
            
            0000000000401080 <_dl_relocate_static_pie>:
              401080:	f3 0f 1e fa          	endbr64 
              401084:	c3                   	ret    
              401085:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
              40108c:	00 00 00 
              40108f:	90                   	nop
            
            0000000000401090 <deregister_tm_clones>:
              401090:	b8 30 40 40 00       	mov    eax,0x404030
              401095:	48 3d 30 40 40 00    	cmp    rax,0x404030
              40109b:	74 13                	je     4010b0 <deregister_tm_clones+0x20>
              40109d:	b8 00 00 00 00       	mov    eax,0x0
              4010a2:	48 85 c0             	test   rax,rax
              4010a5:	74 09                	je     4010b0 <deregister_tm_clones+0x20>
              4010a7:	bf 30 40 40 00       	mov    edi,0x404030
              4010ac:	ff e0                	jmp    rax
              4010ae:	66 90                	xchg   ax,ax
              4010b0:	c3                   	ret    
              4010b1:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
              4010b8:	00 00 00 00 
              4010bc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
            
            00000000004010c0 <register_tm_clones>:
              4010c0:	be 30 40 40 00       	mov    esi,0x404030
              4010c5:	48 81 ee 30 40 40 00 	sub    rsi,0x404030
              4010cc:	48 89 f0             	mov    rax,rsi
              4010cf:	48 c1 ee 3f          	shr    rsi,0x3f
              4010d3:	48 c1 f8 03          	sar    rax,0x3
              4010d7:	48 01 c6             	add    rsi,rax
              4010da:	48 d1 fe             	sar    rsi,1
              4010dd:	74 11                	je     4010f0 <register_tm_clones+0x30>
              4010df:	b8 00 00 00 00       	mov    eax,0x0
              4010e4:	48 85 c0             	test   rax,rax
              4010e7:	74 07                	je     4010f0 <register_tm_clones+0x30>
              4010e9:	bf 30 40 40 00       	mov    edi,0x404030
              4010ee:	ff e0                	jmp    rax
              4010f0:	c3                   	ret    
              4010f1:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
              4010f8:	00 00 00 00 
              4010fc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
            
            0000000000401100 <__do_global_dtors_aux>:
              401100:	f3 0f 1e fa          	endbr64 
              401104:	80 3d 25 2f 00 00 00 	cmp    BYTE PTR [rip+0x2f25],0x0        # 404030 <__TMC_END__>
              40110b:	75 13                	jne    401120 <__do_global_dtors_aux+0x20>
              40110d:	55                   	push   rbp
              40110e:	48 89 e5             	mov    rbp,rsp
              401111:	e8 7a ff ff ff       	call   401090 <deregister_tm_clones>
              401116:	c6 05 13 2f 00 00 01 	mov    BYTE PTR [rip+0x2f13],0x1        # 404030 <__TMC_END__>
              40111d:	5d                   	pop    rbp
              40111e:	c3                   	ret    
              40111f:	90                   	nop
              401120:	c3                   	ret    
              401121:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
              401128:	00 00 00 00 
              40112c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
            
            0000000000401130 <frame_dummy>:
              401130:	f3 0f 1e fa          	endbr64 
              401134:	eb 8a                	jmp    4010c0 <register_tm_clones>
            
            **0000000000401136 <main>:**
              401136:	f3 0f 1e fa          	endbr64 
              40113a:	55                   	push   rbp
              40113b:	48 89 e5             	mov    rbp,rsp
              **40113e:	48 8d 05 bf 0e 00 00 	lea    rax,[rip+0xebf]        # 402004 <_IO_stdin_used+0x4>**
              401145:	48 89 c7             	mov    rdi,rax
              **401148:	e8 f3 fe ff ff       	call   401040 <puts@plt>**
              40114d:	b8 00 00 00 00       	mov    eax,0x0
              401152:	5d                   	pop    rbp
              401153:	c3                   	ret    
            
            Disassembly of section .fini:
            
            0000000000401154 <_fini>:
              401154:	f3 0f 1e fa          	endbr64 
              401158:	48 83 ec 08          	sub    rsp,0x8
              40115c:	48 83 c4 08          	add    rsp,0x8
              401160:	c3                   	ret
            ```
            
            실제 실행 가능한 파일에는 참조가 모두 해결되었다. 또한 프로그램 초기화, 공유 라이브러리 호출등과 관련된 코드가 모두 포함되었다.
            
        - **바이너리가 스트립되었을때**
            
            ```bash
            **$ objdump -M intel -d out_strip**    
            
            out_strip:     file format elf64-x86-64
            
            **Disassembly of section .init:**
            
            0000000000401000 <.init>:
              401000:	f3 0f 1e fa          	endbr64 
              401004:	48 83 ec 08          	sub    rsp,0x8
              401008:	48 8b 05 e9 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fe9]        # 403ff8 <puts@plt+0x2fb8>
              40100f:	48 85 c0             	test   rax,rax
              401012:	74 02                	je     401016 <puts@plt-0x2a>
              401014:	ff d0                	call   rax
              401016:	48 83 c4 08          	add    rsp,0x8
              40101a:	c3                   	ret    
            
            **Disassembly of section .plt:**
            
            0000000000401020 <.plt>:
              401020:	ff 35 e2 2f 00 00    	push   QWORD PTR [rip+0x2fe2]        # 404008 <puts@plt+0x2fc8>
              401026:	f2 ff 25 e3 2f 00 00 	bnd jmp QWORD PTR [rip+0x2fe3]        # 404010 <puts@plt+0x2fd0>
              40102d:	0f 1f 00             	nop    DWORD PTR [rax]
              401030:	f3 0f 1e fa          	endbr64 
              401034:	68 00 00 00 00       	push   0x0
              401039:	f2 e9 e1 ff ff ff    	bnd jmp 401020 <puts@plt-0x20>
              40103f:	90                   	nop
            
            **Disassembly of section .plt.sec:**
            
            **0000000000401040 <puts@plt>:
              401040:	f3 0f 1e fa          	endbr64 
              401044:	f2 ff 25 cd 2f 00 00 	bnd jmp QWORD PTR [rip+0x2fcd]        # 404018 <puts@plt+0x2fd8>
              40104b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]**
            
            **Disassembly of section .text:**
            
            0000000000401050 <.text>:
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
              401068:	48 c7 c7 36 11 40 00 	mov    rdi,0x401136
              40106f:	ff 15 7b 2f 00 00    	call   QWORD PTR [rip+0x2f7b]        # 403ff0 <puts@plt+0x2fb0>
              401075:	f4                   	hlt    
              401076:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
              40107d:	00 00 00 
              401080:	f3 0f 1e fa          	endbr64 
              401084:	c3                   	ret    
              401085:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
              40108c:	00 00 00 
              40108f:	90                   	nop
              401090:	b8 30 40 40 00       	mov    eax,0x404030
              401095:	48 3d 30 40 40 00    	cmp    rax,0x404030
              40109b:	74 13                	je     4010b0 <puts@plt+0x70>
              40109d:	b8 00 00 00 00       	mov    eax,0x0
              4010a2:	48 85 c0             	test   rax,rax
              4010a5:	74 09                	je     4010b0 <puts@plt+0x70>
              4010a7:	bf 30 40 40 00       	mov    edi,0x404030
              4010ac:	ff e0                	jmp    rax
              4010ae:	66 90                	xchg   ax,ax
              4010b0:	c3                   	ret    
              4010b1:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
              4010b8:	00 00 00 00 
              4010bc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
              4010c0:	be 30 40 40 00       	mov    esi,0x404030
              4010c5:	48 81 ee 30 40 40 00 	sub    rsi,0x404030
              4010cc:	48 89 f0             	mov    rax,rsi
              4010cf:	48 c1 ee 3f          	shr    rsi,0x3f
              4010d3:	48 c1 f8 03          	sar    rax,0x3
              4010d7:	48 01 c6             	add    rsi,rax
              4010da:	48 d1 fe             	sar    rsi,1
              4010dd:	74 11                	je     4010f0 <puts@plt+0xb0>
              4010df:	b8 00 00 00 00       	mov    eax,0x0
              4010e4:	48 85 c0             	test   rax,rax
              4010e7:	74 07                	je     4010f0 <puts@plt+0xb0>
              4010e9:	bf 30 40 40 00       	mov    edi,0x404030
              4010ee:	ff e0                	jmp    rax
              4010f0:	c3                   	ret    
              4010f1:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
              4010f8:	00 00 00 00 
              4010fc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
              401100:	f3 0f 1e fa          	endbr64 
              401104:	80 3d 25 2f 00 00 00 	cmp    BYTE PTR [rip+0x2f25],0x0        # 404030 <puts@plt+0x2ff0>
              40110b:	75 13                	jne    401120 <puts@plt+0xe0>
              40110d:	55                   	push   rbp
              40110e:	48 89 e5             	mov    rbp,rsp
              401111:	e8 7a ff ff ff       	call   401090 <puts@plt+0x50>
              401116:	c6 05 13 2f 00 00 01 	mov    BYTE PTR [rip+0x2f13],0x1        # 404030 <puts@plt+0x2ff0>
              40111d:	5d                   	pop    rbp
              40111e:	c3                   	ret    
              40111f:	90                   	nop
              401120:	c3                   	ret    
              401121:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
              401128:	00 00 00 00 
              40112c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
              401130:	f3 0f 1e fa          	endbr64 
              401134:	eb 8a                	jmp    4010c0 <puts@plt+0x80>
              401136:	f3 0f 1e fa          	endbr64 
              40113a:	55                   	push   rbp
              40113b:	48 89 e5             	mov    rbp,rsp
              40113e:	48 8d 05 bf 0e 00 00 	lea    rax,[rip+0xebf]        # 402004 <puts@plt+0xfc4>
              401145:	48 89 c7             	mov    rdi,rax
              401148:	e8 f3 fe ff ff       	call   401040 <puts@plt>
              40114d:	b8 00 00 00 00       	mov    eax,0x0
              401152:	5d                   	pop    rbp
              401153:	c3                   	ret    
            
            **Disassembly of section .fini:**
            
            0000000000401154 <.fini>:
              401154:	f3 0f 1e fa          	endbr64 
              401158:	48 83 ec 08          	sub    rsp,0x8
              40115c:	48 83 c4 08          	add    rsp,0x8
              401160:	c3                   	ret
            ```
            
            기본적인 section 정보는 남아있지만 모든 함수들의 정보는 사라져서 하나의 커다란 코드 구문으로 병합되어있다.
            
            예외적으로 plt section의 함수들의 정보는 보존되어있다.
            
- **바이너리 로딩과 실행**
    - **인터프리터와 지연바인딩**
        
        ![Untitled 1](https://user-images.githubusercontent.com/104804087/224695616-4dbfdc9c-bf03-453b-952a-5e84e0e2db57.png)
        ```bash
        **[-p <number or name>|--string-dump=<number or name>]**
        **$ readelf -p .interp a.out** 
        
        String dump of section '.interp':
          [     0]  **/lib64/ld-linux-x86-64.so.2 <- 실행 할 인터프리터의 경로**
        ```
        
        바이너리 파일을 실행하면 우선 **.interp Section**의 값을 통해 인터프리터의 경로를 지정한다. 인터프리터가 선정되면 커널이 인터프리터에 제어 권한을 부여하고 인터프리터는 실행된 바이너리(프로세스)에 실행 권한을 부여한다. 그후 인터프리터는 특정 함수에 대한 수요가 가장 처음 발생 하는 순간 해당 함수의 주소를 공유 라이브러리에서 찾는다(**mmap 과 같은 함수**를 통해) 그리고 실행된 바이너리(프로세스)의 코드 영역에 특정 함수의 정확한 주소 값을 채워 넣음으로써 재배치 과정을 완료한다**.(지연 바인딩)(lazy binding)**
        
    - **elf/PE format의 존재이유**
        
        모든 바이너리 파일은 메모리에 적재될때는 디스크와 반드시 일대일로 대응되지 않는다.
        
        예를 들어 대용량 바이너리 데이터가 0으로 되어있다면 디스크에 저장될때는 공간 절약을 위해 0모두를 저장하지 않는다. 그러나 메모리에 적재될때는 모두0으로 정확하게 로딩한다. 또한 디스크에 저장될때에와 메모리에 적재될때 각 영역들의 순서가 뒤바뀔수도 있고 어떤 영역은 로딩이 되지 않을 수도 있다.
        
        모든 바이너리에 따라 이 형태가 다르므로 이를 정의하는것이 **elf(Linux) format / PE (Windows) format**이다.
        
- **연습 문제**
    - **함수의 위치 찾기**
        
        ![Untitled](1%E1%84%8C%E1%85%A1%E1%86%BC%20%E1%84%87%E1%85%A1%E1%84%8B%E1%85%B5%E1%84%82%E1%85%A5%E1%84%85%E1%85%B5%E1%84%85%E1%85%A1%E1%86%AB%20%E1%84%86%E1%85%AE%E1%84%8B%E1%85%A5%E1%86%BA%E1%84%8B%E1%85%B5%E1%86%AB%E1%84%80%E1%85%A1%2016f826f24b7d4e98a7423367b52ff16d/Untitled%202.png)
        
        [풀이](https://www.notion.so/f0f0278ab48642f1a9ec04cc65687075)
        
    - **섹션 정보**
        
        ![Untitled](1%E1%84%8C%E1%85%A1%E1%86%BC%20%E1%84%87%E1%85%A1%E1%84%8B%E1%85%B5%E1%84%82%E1%85%A5%E1%84%85%E1%85%B5%E1%84%85%E1%85%A1%E1%86%AB%20%E1%84%86%E1%85%AE%E1%84%8B%E1%85%A5%E1%86%BA%E1%84%8B%E1%85%B5%E1%86%AB%E1%84%80%E1%85%A1%2016f826f24b7d4e98a7423367b52ff16d/Untitled%203.png)
        
        [풀이](https://www.notion.so/45672532da51427ebeeb514c578c3ddb)
        

[이전 정리](https://www.notion.so/e51c97ccd2e24b62b90d81bb511781d8)
