# 13장 PE File Format

```
**PE File Format**
├── **PE File Format Overview**
├── **MS-DOS headers : IMAGE_DOS_HEADER**
│   ├── MS-DOS header
│   └── MS-DOS stub
├── **PE headers : IMAGE_NT_HEADERS64**
│   ├── PE Signature : **Signature**
│   ├── PE file header : **IMAGE_FILE_HEADER**
│   └── PE optional header : **IMAGE_OPTIONAL_HEADER64**
│       ├── IMAGE_DATA_DIRECTORY를 제외한 항목
│       └── IMAGE_DATA_DIRECTORY
├── **Section headers : IMAGE_SECTION_HEADER**
├── **Sections**
│   ├── **.edata section : Export Table (Loading Image Only) & kernel32.dll x64dbg 실습**
│   ├── .idata section : Import Table
│   ├── .rsrc section : Resource Table
│   ├── .pdata section : Exception Table
│   ├── Certificate Table (Loading Image Only)
│   ├── .reloc section : Base Relocation Table (Loading Image Only)
│   ├── .debug section : Debug
│   ├── Architecture : Reserved
│   ├── Global Ptr
│   ├── .tls seciton : TLS Table
│   ├── Load Config Table (Loading Image Only)
│   ├── Bound Import
│   ├── **IAT : Import Address Table & notepad.exe x64dbg 실습**
│   ├── Delay Import Descriptor : Delay-Load Import Tables (Loading Image Only)
│   ├── .cormeta section : CLR Runtime Header (Object Only)
│   └── Reserved
├── **PE Padding**
└── **연습 문제**
    ├── 수동으로 헤더 검사하기
    ├── 디스크 저장시와 메모리 적재 시의 차이
    └── PE vs. ELF
```

- **PE File Format Overview**
    
    [PE Format - Win32 apps](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
    
    ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled.png)
    
- **MS-DOS headers : IMAGE_DOS_HEADER**
    - **MS-DOS header**
        
        ```c
        //WinNT.h
        typedef struct _IMAGE_DOS_HEADER {
            WORD  e_magic;      /* 00: MZ Header signature */
            WORD  e_cblp;       /* 02: Bytes on last page of file */
            WORD  e_cp;         /* 04: Pages in file */
            WORD  e_crlc;       /* 06: Relocations */
            WORD  e_cparhdr;    /* 08: Size of header in paragraphs */
            WORD  e_minalloc;   /* 0a: Minimum extra paragraphs needed */
            WORD  e_maxalloc;   /* 0c: Maximum extra paragraphs needed */
            WORD  e_ss;         /* 0e: Initial (relative) SS value */
            WORD  e_sp;         /* 10: Initial SP value */
            WORD  e_csum;       /* 12: Checksum */
            WORD  e_ip;         /* 14: Initial IP value */
            WORD  e_cs;         /* 16: Initial (relative) CS value */
            WORD  e_lfarlc;     /* 18: File address of relocation table */
            WORD  e_ovno;       /* 1a: Overlay number */
            WORD  e_res[4];     /* 1c: Reserved words */
            WORD  e_oemid;      /* 24: OEM identifier (for e_oeminfo) */
            WORD  e_oeminfo;    /* 26: OEM information; e_oemid specific */
            WORD  e_res2[10];   /* 28: Reserved words */
            DWORD e_lfanew;     /* 3c: Offset to extended header */
        } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
        ```
        
        1981년에 출시한 MS-DOS와의 호환성을 위해 DOS Header를 삽입
        
        MS-DOS header의 주요 역할은 만약 **PE 바이너리가 MS-DOS 환경에서 실행**될때, 해당 프로그램의 **main 함수가 호출되는 대신 MS-DOS stub을 수행**하도록 한다.
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%201.png)
        
        - e_magic : MS-DOS Header 매직 코드
        - **e_lfanew** : **PE 헤더의 파일 시작 오프셋(0xF0)**
    - **MS-DOS stub**
        
        PE파일이 **MS-DOS 환경에서 실행되려 할때, 메인 함수가 호출되는 대신 DOS Stub를 호출**
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%202.png)
        
- **PE headers : IMAGE_NT_HEADERS64**
    
    ```c
    typedef struct _IMAGE_NT_HEADERS64 {
      DWORD Signature;
      IMAGE_FILE_HEADER FileHeader;
      IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    } IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
    ```
    
    ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%203.png)
    
    ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%204.png)
    
    ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%205.png)
    
    - **PE Signature : Signature**
        
        `PE\0\0`
        
        ⇒ PE 시그니처 문자열(elf의 Magic코드와 유사)
        
    - **PE file header : IMAGE_FILE_HEADER**
        
        ```c
        typedef struct _IMAGE_FILE_HEADER {
          WORD  Machine;
          WORD  NumberOfSections;
          DWORD TimeDateStamp;
          DWORD PointerToSymbolTable;
          DWORD NumberOfSymbols;
          WORD  SizeOfOptionalHeader;
          WORD  Characteristics;
        } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
        ```
        
        - **Machine : PE 바이너리 파일이 실행될 시스템의 아키텍쳐**
        - **NumberOfSections : Section Header table의 항목수**
        - **SizeOfOptionalHeader : optional Header의 크기**
        - **Characteristics : 해당 바이너리의 엔디안, DLL 여부, 스트립 여부등의 플래그**
            
             [PE 바이너리의 플래그](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics)
            
    - **PE optional header : IMAGE_OPTIONAL_HEADER64**
        
        ```c
        typedef struct _IMAGE_OPTIONAL_HEADER64 {
          WORD  Magic; /* 0x20b */
          BYTE MajorLinkerVersion;
          BYTE MinorLinkerVersion;
          DWORD SizeOfCode;
          DWORD SizeOfInitializedData;
          DWORD SizeOfUninitializedData;
          DWORD AddressOfEntryPoint;
          DWORD BaseOfCode;
          ULONGLONG ImageBase;
          DWORD SectionAlignment;
          DWORD FileAlignment;
          WORD MajorOperatingSystemVersion;
          WORD MinorOperatingSystemVersion;
          WORD MajorImageVersion;
          WORD MinorImageVersion;
          WORD MajorSubsystemVersion;
          WORD MinorSubsystemVersion;
          DWORD Win32VersionValue;
          DWORD SizeOfImage;
          DWORD SizeOfHeaders;
          DWORD CheckSum;
          WORD Subsystem;
          WORD DllCharacteristics;
          ULONGLONG SizeOfStackReserve;
          ULONGLONG SizeOfStackCommit;
          ULONGLONG SizeOfHeapReserve;
          ULONGLONG SizeOfHeapCommit;
          DWORD LoaderFlags;
          DWORD NumberOfRvaAndSizes;
          IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
        } IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
        ```
        
        - **IMAGE_DATA_DIRECTORY를 제외한 항목**
            
            ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%206.png)
            
            - **Magic Code** : PE 32bits : 0x010B, PE 64bits : 0x020B
            - **AddressOfEntryPoint : Entry Point의 RVA**
            - **ImageBase : 바이너리를 로드해야 할 가상 주소 정보(베이스 가상 주소)**
            - **SectionAlignment : 메모리에서 Section의 최소단위**
            - **FileAlignment : 파일(이미지)에서 Section의 최소단위**
            - **SizeOIfmage : PE파일이 메모리에 로딩 되었을때, 가상 메모리에서 PE Image의 크기**
            - **SizeOfHeaders : PE Header의 전체크기. 즉, 이 값이 가리키는곳에서 첫번째 section이 나온다.**
            - **SubSystem**
                
                ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%207.png)
                
            - **BaseOfCode : Code Section의 가상 주소(RVA)**
            - **NumberOfRvaAndSize : IMAGE_DATA_DIRECTORY 배열의 개수**
        - **IMAGE_DATA_DIRECTORY**
            
            로더의 바로가기 역할을 수행한다. **Section Header table을 반복적으로 탐색하지 않고도 이 table을 이용해 바로 Section에 접근가능**
            
            ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%208.png)
            
            - **VirtualAddress : Section의 시작 RVA**
            - **Size : Section의 크기**
            
            ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%209.png)
            
- **Section Headers : IMAGE_SECTION_HEADER**
    
    ```c
    typedef struct _IMAGE_SECTION_HEADER {
      BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
      union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
      } Misc;
      DWORD VirtualAddress;
      DWORD SizeOfRawData;
      DWORD PointerToRawData;
      DWORD PointerToRelocations;
      DWORD PointerToLinenumbers;
      WORD  NumberOfRelocations;
      WORD  NumberOfLinenumbers;
      DWORD Characteristics;
    } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
    ```
    
    ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2010.png)
    
    ELF와 달리 Name 배열로 직접 이름을 지정한다.
    
    PE 바이너리는 ELF 와는 달리 Section과 Segment를 명시적으로 구분하지는 않는다. 
    
    - **VirtualSize : 메모리에서 Section이 차지하는 크기**
    - **VirtualAddress : 메모리에서 Section의 시작주소 RVA**
    - **SizeOfRawData : 파일에서 Section이 차지하는 크기**
    - **PointerToRawData : 파일에서 Section의 시작 위치**
    - **Characteristics : section의 속성**
- **Sections**
    
    현재 분석하는 프로그램 notepad.exe는 Section의수가 7개이므로 IMAGE_SECTION_HEADER(40)크기 : 280
    
    - **.edata section : Export Table (Loading Image Only) & kernel32.dll x64dbg 실습**
        
        ```bash
        **C:\> explorer.exe kernel32.dll**
        [+] PE IMAGE INFORMATION 
        
        [+] Architecture x64 
        
        [+] DOS HEADER 
        	e_magic : 0x5A4D
        	e_cblp : 0x90
        	e_cp : 0x3
        	e_crlc : 0x0
        	e_cparhdr : 0x4
        	e_minalloc : 0x0
        	e_maxalloc : 0xFFFF
        	e_ss : 0x0
        	e_sp : 0xB8
        	e_csum : 0x0
        	e_ip : 0x0
        	e_cs : 0x0
        	e_lfarlc : 0x40
        	e_ovno : 0x0
        	e_oemid : 0x0
        	e_oeminfo : 0x0
        	e_lfanew : 0xE8
        
        [+] NT HEADER
        	Signature : 0x4550
        
        [+] FILE HEADER
        	Machine : 0x8664
        	NumberOfSections : 0x7
        	TimeDateStamp  : 0x4D6D72D1
        	PointerToSymbolTable   : 0x0
        	NumberOfSymbols   : 0x0
        	SizeOfOptionalHeader   : 0xF0
        	Characteristics  : 0x2022 (DLL)
        
        [+] OPTIONAL HEADER
        	Magic : 0x20B
        	MajorLinkerVersion : 0xE
        	MinorLinkerVersion : 0x14
        	SizeOfCode : 0x7D400
        	SizeOfInitializedData : 0x3A600
        	SizeOfUninitializedData : 0x0
        	AddressOfEntryPoint : 0x170D0
        	BaseOfCode : 0x1000
        	ImageBase : 0x80000000
        	BSectionAlignment : 0x1000
        	FileAlignment : 0x200
        	MajorOperatingSystemVersion : 0xA
        	MinorOperatingSystemVersion : 0x0
        	MajorImageVersion : 0xA
        	MinorImageVersion : 0x0
        	MajorSubsystemVersion : 0xA
        	MinorSubsystemVersion : 0x0
        	Win32VersionValue : 0x0
        	SizeOfImage : 0xBD000
        	SizeOfHeaders : 0x400
        	CheckSum : 0xBC204
        	Subsystem : 0x3 (CONSOLE APP)
        	DllCharacteristics : 0x4160
        	SizeOfStackReserve : 0x40000
        	SizeOfStackCommit : 0x1000
        	SizeOfHeapReserve : 0x100000
        	SizeOfHeapCommit : 0x1000
        	LoaderFlags : 0x0
        	**NumberOfRvaAndSizes : 0x10 # DataDirectory의 개수**
        	DataDirectory : 0x12FF6C8
        
        	**DataDirectory (Export Table) VirtualAddress : 0x99080**
        	DataDirectory (Export Table) Size : 0xDF0C
        
        	DataDirectory (Import Table) VirtualAddress : 0xA6F8C
        	DataDirectory (Import Table) Size : 0x794
        
        	DataDirectory (Ressource Table) VirtualAddress : 0xBB000
        	DataDirectory (Ressource Table) Size : 0x520
        
        	DataDirectory (Exception Entry) VirtualAddress : 0xB4000
        	DataDirectory (Exception Entry) Size : 0x5550
        
        	DataDirectory (Security Entry) VirtualAddress : 0xB7000
        	DataDirectory (Security Entry) Size : 0x4030
        
        	DataDirectory (Relocation Table) VirtualAddress : 0xBC000
        	DataDirectory (Relocation Table) Size : 0x300
        
        	DataDirectory (Debug Entry) VirtualAddress : 0x86930
        	DataDirectory (Debug Entry) Size : 0x70
        
        	DataDirectory (Configuration Entry) VirtualAddress : 0x7F7F0
        	DataDirectory (Configuration Entry) Size : 0x118
        
        	DataDirectory (IAT) VirtualAddress : 0x807C0
        	DataDirectory (IAT) Size : 0x2A58
        
        	DataDirectory (Delay Import Descriptor) VirtualAddress : 0x98E40
        	DataDirectory (Delay Import Descriptor) Size : 0x60
        
        [+] PE IMAGE SECTIONS
        
        	SECTION : .text
        		Misc (PhysicalAddress) : 0x7D3FB
        		Misc (VirtualSize) : 0x7D3FB
        		VirtualAddress : 0x1000
        		SizeOfRawData : 0x7D400
        		PointerToRawData : 0x400
        		PointerToRelocations : 0x0
        		PointerToLinenumbers : 0x0
        		NumberOfRelocations : 0x0
        		NumberOfLinenumbers : 0x0
        		Characteristics : 0x60000020 (EXECUTE | READ)
        
        	SECTION : .rdata
        		Misc (PhysicalAddress) : 0x32E96
        		Misc (VirtualSize) : 0x32E96
        		VirtualAddress : 0x7F000
        		SizeOfRawData : 0x33000
        		PointerToRawData : 0x7D800
        		PointerToRelocations : 0x0
        		PointerToLinenumbers : 0x0
        		NumberOfRelocations : 0x0
        		NumberOfLinenumbers : 0x0
        		Characteristics : 0x40000040 (READ)
        
        	SECTION : .data
        		Misc (PhysicalAddress) : 0x121C
        		Misc (VirtualSize) : 0x121C
        		VirtualAddress : 0xB2000
        		SizeOfRawData : 0x600
        		PointerToRawData : 0xB0800
        		PointerToRelocations : 0x0
        		PointerToLinenumbers : 0x0
        		NumberOfRelocations : 0x0
        		NumberOfLinenumbers : 0x0
        		Characteristics : 0xC0000040 (READ | WRITE)
        
        	SECTION : .pdata
        		Misc (PhysicalAddress) : 0x5550
        		Misc (VirtualSize) : 0x5550
        		VirtualAddress : 0xB4000
        		SizeOfRawData : 0x5600
        		PointerToRawData : 0xB0E00
        		PointerToRelocations : 0x0
        		PointerToLinenumbers : 0x0
        		NumberOfRelocations : 0x0
        		NumberOfLinenumbers : 0x0
        		Characteristics : 0x40000040 (READ)
        
        	SECTION : .didat
        		Misc (PhysicalAddress) : 0x68
        		Misc (VirtualSize) : 0x68
        		VirtualAddress : 0xBA000
        		SizeOfRawData : 0x200
        		PointerToRawData : 0xB6400
        		PointerToRelocations : 0x0
        		PointerToLinenumbers : 0x0
        		NumberOfRelocations : 0x0
        		NumberOfLinenumbers : 0x0
        		Characteristics : 0xC0000040 (READ | WRITE)
        
        	SECTION : .rsrc
        		Misc (PhysicalAddress) : 0x520
        		Misc (VirtualSize) : 0x520
        		VirtualAddress : 0xBB000
        		SizeOfRawData : 0x600
        		PointerToRawData : 0xB6600
        		PointerToRelocations : 0x0
        		PointerToLinenumbers : 0x0
        		NumberOfRelocations : 0x0
        		NumberOfLinenumbers : 0x0
        		Characteristics : 0x40000040 (READ)
        
        	SECTION : .reloc
        		Misc (PhysicalAddress) : 0x300
        		Misc (VirtualSize) : 0x300
        		VirtualAddress : 0xBC000
        		SizeOfRawData : 0x400
        		PointerToRawData : 0xB6C00
        		PointerToRelocations : 0x0
        		PointerToLinenumbers : 0x0
        		NumberOfRelocations : 0x0
        		NumberOfLinenumbers : 0x0
        		Characteristics : 0x42000040 (READ)
        
        [+] IMPORTED DLL
        
        	DLL NAME : api-ms-win-core-rtlsupport-l1-1-0.dll
        	Characteristics : 0x18C7760
        	OriginalFirstThunk : 0x18C7760
        	TimeDateStamp : 0x181E820
        	ForwarderChain : 0x181E820
        	FirstThunk : 0x18A0800
        
        	Imported Functions : 
        
        		RtlCaptureContext
        		RtlRaiseException
        
        ....
        	
        
        [+] EXPORTED FUNCTIONS
        
        	AcquireSRWLockExclusive
        	AcquireSRWLockShared
        ....
        ```
        
    - **.idata section : Import Table**
        
        
    - **.rsrc section : Resource Table**
        
        
    - **.pdata section : Exception Table**
        
        
    - **Certificate Table (Loading Image Only)**
        
        
    - **.reloc section : Base Relocation Table (Loading Image Only)**
        
        
    - **.debug section : Debug**
        
        
    - **Architecture : Reserved**
        
        
    - **Global Ptr**
        
        
    - **.tls seciton : TLS Table**
        
        
    - **Load Config Table (Loading Image Only)**
        
        
    - **Bound Import**
        
        
    - **IAT : Import Address Table & notepad.exe x64dbg 실습**
        
        
    - **Delay Import Descriptor : Delay-Load Import Tables (Loading Image Only)**
        
        
    - **.cormeta section : CLR Runtime Header (Object Only)**
        
        
    - **Reserved**
        
        
- **PE Padding**
    
    MSVC의 컴파일 옵션 `/hotpatch` 를 사용하면 런타임에 코드를 동적으로 패치할수있다.
    
    모든 함수 앞에 5바이트의 `int3` 명령어를 삽입하고 함수 엔트리 포인트에 2바이트 `nop` 명령어를 삽입하여 총 7바이트의 여유를 만들어놓고 `jmp address` 명령어를 삽입하며 함수의 패치를 적용한다.
    
- **연습 문제**
    - **수동으로 헤더 검사하기**
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2011.png)
        
        [풀이](https://www.notion.so/fc29b754f9f04c0593628a436d48160b)
        
    - **디스크 저장시와 메모리 적재 시의 차이**
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2012.png)
        
        [풀이](https://www.notion.so/a20f314d5ff14678b0fd2bae98f97629)
        
    - **PE vs. ELF**
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2013.png)
        
        [풀이](https://www.notion.so/798a809f0c2848dda447b7258760368f)
        

- **13.3.6. Section Header**
    
    Section의수가 7개이므로 IMAGE_SECTION_HEADER(40)크기 : 280
    
    - **.text Section**
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2014.png)
        
    - **.rdata Section**
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2015.png)
        
    - **.data Section**
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2016.png)
        
    - **.pdata Section**
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2017.png)
        
    - **.didat Section**
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2018.png)
        
    - **.rsrc Section**
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2019.png)
        
    - **.reloc Section**
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2020.png)
        
- **13.4. RVA to RAW**
    - 메모리 적재(Loading) 구조
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2021.png)
        
    1. 주어진 RVA가 속한 Section을 찾는다.
    2. 간단한 비례식을 사용해 파일 오프셋(RAW)을 계산
    
    IMAGE_SECTION_HEADER구조체를 참고하여 RVA(Virtual Address Offset)으로 부터 파일 오프셋값을 계산할수있다.
    
    ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2022.png)
    
    $RVA - VirtualAddress = RAW(File Offset) - PointerToRawData$
    
    - **For Example 1**
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2023.png)
        
        메모리 모델이 다음과 같을때 File Offset값은?
        
        - RVA = 0x5000일때 RAW(File Offset)은?
            
            .text Section에 위치하므로 
            
            RVA(0x5000) - 0x1000(Virtual Address) = RAW - 0x400(PointerToRawData) 
            
            ⇒File Offset = 0x4400 
            
        - RVA = 0x13314일때 RAW(File Offset)은?
            
            .rsrc Section에 위치하므로 
            
            RVA(0x13314) - 0xB000(Virtual Address) = RAW - 0x8400(PointerToRawData)
            
            ⇒File Offset = 0x10714
            
        - RVA = 0xABA8일때 RAW(File Offset)은?
            
            .data Section에 위치하므로 
            
            RVA(0xABA8) - 0x9000(Virtual Address) = RAW -0x7C00(PointerToRawData)
            
            ⇒File Offset = 0x97A8 이값은 rsrc에 속한다. 
            
            **해당 RVA에 대한 RAW값은 정의 할 수 없다. why? Virtual Size값이 SizeOfRawData값보다 크기때문.**
            
    - **For Example 2**
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2021.png)
        
        메모리 구조가 다음과 같을때 RAW값은?
        
        - RVA = 0x36150일때 File Offset값은?
            
            .didat Section에 위치 하므로 
            
            RVA(0x36150) - 0x36000(Virtual Address) = RAW - 0x34000(PointerToRawData)
            
            ⇒ File Offset = 0x34150
            
        - RVA = 0x35300일때 File Offset값은?
            
            .pdata Section에 위치 하므로
            
            RVA(0x35300) - 0x34000(Virtual Address) = RAW - 0x32000(PointerToRawData)
            
            ⇒ File Offset = 0x33300
            
        - RVA = 0x33600일때 File Offset값은?
            
            .data Section에 위치 하므로
            
            RVA(0x33600) - 0x31000(Virtual Address) = RAW - 0x31000(PointerToRawData)
            
            ⇒ File Offset = 0x33600 이값은 .pdata Section에 속한다
            
            **해당 RVA에 대한 RAW값은 정의 할 수 없다. why? Virtual Size값이 SizeOfRawData값보다 크기때문.**
            
- **13.5. IAT : .idata**
    
    **Import Address Table(IAT) :** Windows운영체제의 작동 방식 이며 현대의 운영체제는 보통 이렇게 작동 ; 프로그램에 라이브러리를 포함하지 말고 DLL(Dynamic Linked Library)파일형태로 저장후 한번 Loading되면 **Memory-Mapping** 기술로 다른 Process에서도 공유하여 사용(Shared Library)
    
    - Explicit Linking
        
        **프로그램에서 사용**되는 순간 **DLL Loading**, **사용이 끝나면 해제**
        
    - **Implicit Linking(IAT개념 사용)**
        
        **프로그램이 시작**할때 **DLL Loading**, **프로그램 종료시 해제 ⇒ IAT개념 사용(Memory Mapping)**
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2024.png)
        
        CreateFileW를 호출할때 바로 CreateFileW함수로 가지 않고 
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2025.png)
        
        해당 함수의 주소 매핑은 By **ntdll.dll**
        
        다음과 같이 실제 CreateFileW함수로 이동시켜주는 명령어로 이동한다.
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2026.png)
        
- **13.5.2. IMAGE_IMPORT_DESCRIPTOR with notepad.exe 실습**
    
    **배열의 형태**로 존재한다.
    
    ![ImageImportDescriptor.png](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/ImageImportDescriptor.png)
    
    **IAT(Image Import Table)입력 순서(First Thunk값 채우는 방법)**
    
    1. IMPORT_IMAGE_DESCRIPTOR(IID)의 Name멤버를 읽어 라이브러리 이름 문자열 “kernel32.dll”을 얻는다.
    2. 해당 라이브러리를 로딩한다. LoadLibrary(”kernel32.dll”)
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2027.png)
        
    3. IID의 OriginalFirstThunk 멤버를 읽어서 Import Name Table의 RVA를 얻는다.
    4. Import Name Table(INT)에서 배열의 값을 하나씩 읽어 IMAGE_IMPORT_BY_NAME의 RVA를 얻는다.
    5. IMAGE_IMPORT_BY_NAME의 Hint또는Name항목을 이용하여 해당 함수의 시작 주소를 얻는다. **GetProcAddress(”GetCurrentThreadid”)**
    6. IID의 FirstThunk(IAT)멤버를 읽어서 IAT(Import Address Table) RVA를 얻는다.
    7. 해당 IAT배열 값위에 앞서 구한 함수 주소**(GetProcAddress(”kernel32.dll”,”FunctionName”)**를 write한다.
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2028.png)
        
    8. INT(Import Name Table)이 끝날때 까지 4 ~ 7 과정을 반복한다.
- **x64dbg에서 결과 확인**
    
    **ImageBase값 : 0x00007FF7D67D0000**
    
    ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2029.png)
    
    - EntryPoint
        
        **0x00007FF7D67D0000 + 0x1b60 = 0x00007FF7D67D1B60**
        
        ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2030.png)
        
    - .text Section
        
        Start RVA : **0x00007FF7D67D0000 + 0x1000 = 0x00007FF7D67D1000**
        
    - .rdata Section
        
        Start RVA : **0x00007FF7D67D0000 + 0x00027000 = 0x00007FF7D67F7000**
        
    - .data Section
        
        Start RVA : **0x00007FF7D67D0000 + 0x00031000 = 0x00007FF7D6801000**
        
    - .pdata Section
        
        Start RVA : **0x00007FF7D67D0000 + 0x00034000 = 0x00007FF7D6804000**
        
    - .didat Section
        
        Start RVA : **0x00007FF7D67D0000 + 0x00036000 = 0x00007FF7D6806000**
        
    - .rsrc Section
        
        Start RVA : **0x00007FF7D67D0000 + 0x00037000 = 0x00007FF7D6807000**
        
    - .reloc Section
        
        Start RVA : **0x00007FF7D67D0000 + 0x00056000 = 0x00007FF7D6826000**
        
- **13.6. EAT : .edata**
    
    **Export Address Table(EAT)** : 라이브러리 파일에서 제공하는 함수를 다른 프로그램에서 가져다 사용할 수 있도록 하는 기술. EAT를 통해서만 Export하는 함수의 주소를 정확히 구할 수 있다.
    
- **13.6.1. IMAGE_EXPORT_DIRECTORY with kernel32.dll 실습**
    
    **PE파일에 하나만 존재**
    
    ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2031.png)
    
    **GetProcAddress()함수**는 **EAT(Export Address Table)을 참조**하여 **원하는 함수의 주소**를 구한다.
    
    1. AddressOfNames멤버를 이용해 “함수 이름 배열”로 이동
    2. 문자열 비교(strcmp)를 통해 원하는 함수의 이름을 찾고 이때의 인덱스를(name_index) 반환
    3. AddressOfNameOrdinals멤버를 이용해 ordinal배열로 이동
    4. ordinal 배열에서 name_index로 ordinal값을 찾는다.
    5. AddressOfFunction멤버를 이용해 함수 주소 배열(EAT)로 이동
    6. 함수 주소 배열(EAT)에서 ordinal값을 인덱스로 하는 원하는 함수의 주소를 얻는다.
- **x64dbg에서 결과 확인**
    
    **ImageBase값 : 0x00007FFAD2C80000**
    
    ![Untitled](13%E1%84%8C%E1%85%A1%E1%86%BC%20PE%20File%20Format%205f3217e8999c41fdba563f3e298b293a/Untitled%2032.png)
