#include <fcntl.h>
#include <gelf.h>
#include <getopt.h>
#include <libelf.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ABITAG_NAME ".note.ABI-tag"
#define SHSTRTAB_NAME ".shstrtab"

/**
 * @struct 대상 ELF 바이너리를 수정하는데 필요한 데이터
 */
typedef struct elf_data {
    int fd;         /** @memberof ELF 바이너리의 파일 디스크립터 */
    Elf *e;         /** @memberof libelf의 elf 디스크립터*/
    int bits;       /** @memberof ELF 바이너리의 32/64 비트 */
    GElf_Ehdr ehdr; /** @memberof ELF Executable Header*/
} elf_data_t;

/**
 * @struct ELF 대상 바이너리에 삽입하기 위한 위치 정보와 방법
 */
typedef struct inject_data {
    size_t pidx;    /** @memberof 덮어쓰려는 program header의 index*/
    GElf_Phdr phdr; /** @memberof 덮어쓰려는 progream hedaer*/

    size_t sidx;    /** @memberof 덮어쓰려는 section header의 index*/
    Elf_Scn *scn;   /** @memberof 덮어쓰려는 section*/
    GElf_Shdr shdr; /** @memberof 덮어쓰려는 section header*/
    off_t shstroff; /** @memberof 덮어쓰려는 section name의 index*/

    char *code; /** @memberof 삽입할 코드*/
    size_t len; /** @memberof 삽입할 코드의 바이트 수*/

    long entry; /** @memberof 새로운 Entry Point 없으면 -1*/

    off_t off; /** @memberof 삽입할 코드까지의 file offset*/

    size_t secaddr; /** @memberof 삽입할 코드 section의 vaddr*/
    char *secname;  /** @memberof 삽입할 코드 section의 이름*/
} inject_data_t;
/**
 * @brief ELF 바이너리에 실제로 코드를 삽입하는 함수
 * @param fd ELF 바이너리 파일 디스크립터
 * @param inject 삽입할 실제 정보
 * @return 성공시 0 / 실패시 -1
 */
int inject_code(int fd, inject_data_t *inject);

/**
 * @brief 덮어씌울 PT_NOTE Segment를 찾고, inject에 그 위치 정보를 기록한다.
 * @param elf 대상 ELF 바이너리
 * @param inject 삽입할 위치 및 정보
 * @return  성공시 0 / 실패시 -1
 */
int find_rewriteable_segment(elf_data_t *elf, inject_data_t *inject);

/**
 * @brief 바이너리 끝 부분에 코드를 삽입한다.
 * @param elf 대상 ELF 바이너리
 * @param inject 삽입할 위치 및 정보
 * @return 성공시 0 / 실패시 -1
 */
int write_code(elf_data_t *elf, inject_data_t *inject);

/**
 * @brief section header를 덮어쓴다.
 * @param elf 대상 ELF 바이너리
 * @param inject 삽입할 위치 및 정보
 * @return 성공시 0 / 실패시 -1
 */
int rewrite_code_section(elf_data_t *elf, inject_data_t *inject);

/**
 * @brief ELF 바이너리에 section header를 수정한다.
 * @param elf 대상 ELF 바이너리
 * @param scn section 정보
 * @param shdr section header 정보
 * @param sidx section header의 name index
 * @return 성공시 0 / 실패시 -1
 */
int write_shdr(elf_data_t *elf, Elf_Scn *scn, GElf_Shdr *shdr, size_t sidx);

/**
 * @brief section name을 덮어쓴다.
 * @param elf
 * @param inject
 * @return 성공시 0 / 실패시 -1
 */
int rewrite_section_name(elf_data_t *elf, inject_data_t *inject);

/**
 * @brief program header를 덮어쓴다.
 * @param elf
 * @param inject
 * @return 성공시 0 / 실패시 -1
 */
int rewrite_code_segment(elf_data_t *elf, inject_data_t *inject);

/**
 * @brief ELF 바이너리에 program header를 수정한다.
 * @param elf 대상 ELF 바이너리
 * @param inject 삽입하고자하는 ELF 정보
 * @return 성공시 0 / 실패시 -1
 */
int write_phdr(elf_data_t *elf, inject_data_t *inject);

/**
 * @brief ELF 바이너리의 EP를 수정한다.
 * @param elf 대상 ELF 바이너리
 * @param inject 삽입하고자하는 ELF 정보
 * @return 성공시 0 / 실패시 -1
 */
int rewrite_entry_point(elf_data_t *elf, inject_data_t *inject);

/**
 * @brief ELF 바이너리의 ELF Executable Header를 수정한다.
 * @param elf 대상 ELF 바이너리
 * @param inject 삽입하고자하는 ELF 정보
 * @return 성공시 0 / 실패시 -1
 */
int write_ehdr(elf_data_t *elf);

/**
 * @brief 삽입할 section의 가상메모리 주소를 정렬한다.
 * @param inject 정렬할 정보
 */
void align_code(inject_data_t *inject);

/**
 * @brief 섹션을 삽입한후 섹션을 정렬한다.
 * @param elf 대상 ELF 바이너리
 * @param inject 삽입하고자하는 ELF 정보
 * @return 성공시 0 / 실패시 -1
 */
int reorder_shdrs(elf_data_t *elf, inject_data_t *inject);

/**
 * @brief section name을 덮어쓴다
 * @param elf 대상 ELF 바이너리
 * @param inject 삽입하고자하는 ELF 정보
 * @return 성공시 0 / 실패시 -1
 */
int write_secname(elf_data_t *elf, inject_data_t *inject);

int inject_code(int fd, inject_data_t *inject) {
    // 실제 코드를 삽입하는함수, inject_data_t에는 적절한 데이터가 이미 로드됨
    // fd에 inject_data_t를 삽입

    elf_data_t elf;
    int ret;
    elf.fd = fd;
    elf.e = NULL;

    if (elf_version(EV_CURRENT) == EV_NONE) {  // elf version == EV_CURRENT
        fprintf(stderr, "Failed to initialize libelf\n");
        goto fail;
    }

    /* 파일을 읽들 때는 libelf사용, 쓰기 작업은 직접 수행*/
    elf.e = elf_begin(elf.fd, ELF_C_READ, NULL);  // ELF Open : elf의 fd를 READ모드로 읽어 ELF Handle은 알아서 관리
    if (!elf.e) {
        fprintf(stderr, "Not an ELF executable\n");
        goto fail;
    }

    if (elf_kind(elf.e) != ELF_K_ELF) {  // Is Executable ELF?
        fprintf(stderr, "Not an ELF executable\n");
        goto fail;
    }

    ret = gelf_getclass(elf.e);  // 32비트/64비트 정보를 가져옴
    switch (ret) {
        case ELFCLASSNONE:
            fprintf(stderr, "Unknown ELF class\n");
            goto fail;
        case ELFCLASS32:
            elf.bits = 32;
            break;
        default:
            elf.bits = 64;
            break;
    }

    if (!gelf_getehdr(elf.e, &elf.ehdr)) {  // Get ELF Executable Header
        fprintf(stderr, "Failed to get executable header\n");
        goto fail;
    }

    if (find_rewriteable_segment(&elf, inject) < 0) {  // 0. Find PT_NOTE Segment 이게 없으면 아래 부분은 아예 실행 불가능하므로 가장 먼저 수행
        goto fail;
    }

    if (write_code(&elf, inject) < 0) {  // 1. 바이너리 끝부분에 코드를 삽입한다.
        goto fail;
    }

    align_code(inject);  // 가상메모리의 주소를 페이지의 크기 4096의 배수로 정렬한다., 파일 오프셋 크기는 그대로임

    if ((rewrite_code_section(&elf, inject) < 0) || (rewrite_section_name(&elf, inject)) < 0) {  // 2. section header, section name을 덮어쓴다.
        goto fail;
    }

    if (rewrite_code_segment(&elf, inject) < 0) {  // 3. program header를 덮어쓴다.
        goto fail;
    }

    if ((inject->entry >= 0) && (rewrite_entry_point(&elf, inject)) < 0) {  // 4. EP를 수정한다.
        goto fail;
    }

fail:
    ret = -1;

cleanup:
    if (elf.e) {
        elf_end(elf.e);
    }

    return ret;
}

int find_rewriteable_segment(elf_data_t *elf, inject_data_t *inject) {
    int ret;
    size_t i, n;
    ret = elf_getphdrnum(elf->e, &n);  // ELF 파일안에 있는 program header의 개수를 가져온다.
    if (ret != 0) {
        fprintf(stderr, "Cannot find any program headers\n");
        return -1;
    }
    for (i = 0; i < n; i++) {
        if (!gelf_getphdr(elf->e, i /* program header table index */, &inject->phdr /**/)) {  // progream header table로 부터 program header를 얻는다.
            fprintf(stderr, "Failed to get program header\n");
            return -1;
        }

        switch (inject->phdr.p_type) {
            case PT_NOTE:
                inject->pidx = i;  // 인덱스 정보를 기록한다.
                return 0;
            default:
                break;
        }
    }
    fprintf(stderr, "Cannot find segment to rewrite\n");
    return -1;
}

int write_code(elf_data_t *elf, inject_data_t *inject) {
    off_t off;
    size_t n;
    off = lseek(elf->fd, 0, SEEK_END);  // 바이너리의 끝 부분을 찾는다.
    if (off < 0) {
        fprintf(stderr, "lseek failed\n");
        return -1;
    }

    n = write(elf->fd, inject->code, inject->len);  // must be opened APPEND MODE
    if (n != inject->len) {
        fprintf(stderr, "Failed to inject code bytes\n");
        return -1;
    }
    inject->off = off;

    return 0;
}

void align_code(inject_data_t *inject) {
    size_t n;
    n = (inject->off % 4096) - (inject->secaddr % 4096);
    inject->secaddr += n;  // 메모리에 적재될때의 가상메모리값 정렬!!
}

int rewrite_code_section(elf_data_t *elf, inject_data_t *inject) {
    Elf_Scn *scn;
    GElf_Shdr shdr;
    char *s;
    size_t shstrndx;

    if (elf_getshdrstrndx(elf->e, &shstrndx)) {  // ELF Header에서 모든 section의 이름을 가지고 있는 section header의 인덱스 e_shstrndx값을 가져옴
        fprintf(stderr, "Failed to get string table section index\n");
        return -1;
    }

    scn = NULL;
    while ((scn = elf_nextscn(elf->e, scn))) {  // Get ELF Section Header pointer
        if (!gelf_getshdr(scn, &shdr)) {        // save to Section Header -> shdr
            fprintf(stderr, "Failed to get section header\n");
            return -1;
        }
        s = elf_strptr(elf->e, shstrndx, shdr.sh_name);  // Return pointer to string at OFFSET in section INDEX.
        if (!s) {
            fprintf(stderr, "Failed to get section name\n");
            return -1;
        }

        if (!strcmp(s, ABITAG_NAME)) {                  // Is .note.ABI_tag Section Header ?
            shdr.sh_name = shdr.sh_name;                // 문자열 테이블의 오프셋
            shdr.sh_type = SHT_PROGBITS;                // 데이터 또는 코드
            shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;  // 메모리 적재 & 실행가능
            shdr.sh_addr = inject->secaddr;             // 섹션의 가상메모리 주소
            shdr.sh_offset = inject->off;               // 섹션 시작 부분의 파일 오프셋
            shdr.sh_size = inject->len;                 // 섹션 코드의 크기
            shdr.sh_link = 0;                           // 코드 섹션에서는 사용하지 않음
            shdr.sh_info = 0;                           // 코드 섹션에서는 사용하지 않음
            shdr.sh_addralign = 16;                     // 메모리 정렬
            shdr.sh_entsize = 0;                        // 코드 섹션에서는 사용하지 않음

            inject->sidx = elf_ndxscn(scn);  // Get index of section header.
            inject->scn = scn;               // set section pointer

            memcpy(&inject->shdr, &shdr, sizeof(shdr));  // set section header

            if (write_shdr(elf, scn, &shdr, elf_ndxscn(scn)) < 0) {  // section header를 수정한다.
                return -1;
            }

            if (reorder_shdrs(elf, inject) < 0) {  // 정렬한다.
                return -1;
            }
            break;
        }
    }
    if (!scn) {
        fprintf(stderr, "Cannot find section to rewrite\n");
        return -1;
    }
    return 0;
}

int write_shdr(elf_data_t *elf, Elf_Scn *scn, GElf_Shdr *shdr, size_t sidx) {
    off_t off;
    size_t n, shdr_size;
    void *shdr_buf;

    if (!gelf_update_shdr(scn, shdr)) {
        fprintf(stderr, "Failed to update section header\n");
        return -1;
    }

    if (elf->bits == 32) {
        shdr_buf = elf32_getshdr(scn);  // Get section header
        shdr_size = sizeof(Elf32_Shdr);
    } else {
        shdr_buf = elf64_getshdr(scn);  // Get Section Header
        shdr_size = sizeof(Elf64_Shdr);
    }

    if (!shdr_buf) {
        fprintf(stderr, "Failed to get section header\n");
        return -1;
    }

    // 수정할 section header 의 위치
    off = lseek(elf->fd, elf->ehdr.e_shoff + sidx * elf->ehdr.e_shentsize, SEEK_SET);  // section header offset + section header index*Section header table entry size
    if (off < 0) {
        fprintf(stderr, "lseek failed\n");
        return -1;
    }

    n = write(elf->fd, shdr_buf, shdr_size);  // section header에 새로운 정보를 쓴다.
    if (n != shdr_size) {
        fprintf(stderr, "Failed to write section header\n");
        return -1;
    }

    return 0;
}

int rewrite_section_name(elf_data_t *elf, inject_data_t *inject) {
    Elf_Scn *scn;
    GElf_Shdr shdr;
    char *s;
    size_t shstrndx, stroff, strbase;

    if (strlen(inject->secname) > strlen(ABITAG_NAME)) {  // compare Section name length
        fprintf(stderr, "Section name too long!\n");
        return -1;
    }

    if (elf_getshdrstrndx(elf->e, &shstrndx) < 0) {  // Get the section index of the section header string table in the ELF
        fprintf(stderr, "Failed to get string table section index\n");
        return -1;
    }

    stroff = 0;   // section header name index
    strbase = 0;  //.shstrtab offset
    scn = NULL;
    while ((scn = elf_nextscn(elf->e, scn))) {  // 모든 section을 순회한다.
        if (!gelf_getshdr(scn, &shdr)) {        // section의 정보를 shdr에 저장한다.
            fprintf(stderr, "Failed to get section header\n");
            return -1;
        }
        s = elf_strptr(elf->e, shstrndx, shdr.sh_name);  // Return pointer to string at OFFSET in section INDEX.
        if (!s) {
            fprintf(stderr, "Failed to get section name\n");
            return -1;
        }
        if (!strcmp(s, ABITAG_NAME)) {
            stroff = shdr.sh_name;  // set section header name index
        } else if (!strcmp(s, SHSTRTAB_NAME)) {
            strbase = shdr.sh_offset;  //.shstrtab offset
        }
    }

    if (stroff == 0) {
        fprintf(stderr, "Cannot find shstrtab entry for injected section\n");
        return -1;
    } else if (strbase == 0) {
        fprintf(stderr, "Cannot find shstrtab\n");
        return -1;
    }

    inject->shstroff = strbase + stroff;  // 실제 문자열 위치 설정

    if (write_secname(elf, inject) < 0) {  // 섹션 이름 변경
        return -1;
    }
    return 0;
}

int reorder_shdrs(elf_data_t *elf, inject_data_t *inject) {
    int direction, skip;
    size_t i;
    Elf_Scn *scn;
    GElf_Shdr shdr;

    direction = 0;

    scn = elf_getscn(elf->e, inject->sidx - 1);
    if (scn && !gelf_getshdr(scn, &shdr)) {
        fprintf(stderr, "Failed to get section header\n");
        return -1;
    }

    if (scn && shdr.sh_addr > inject->shdr.sh_addr) {
        /* Injected section header must be moved left */
        direction = -1;
    }

    scn = elf_getscn(elf->e, inject->sidx + 1);
    if (scn && !gelf_getshdr(scn, &shdr)) {
        fprintf(stderr, "Failed to get section header\n");
        return -1;
    }

    if (scn && shdr.sh_addr < inject->shdr.sh_addr) {
        /* Injected section header must be moved right */
        direction = 1;
    }

    if (direction == 0) {
        /* Section headers are already in order */
        return 0;
    }

    i = inject->sidx;

    /* Order section headers by increasing address */
    skip = 0;
    for (scn = elf_getscn(elf->e, inject->sidx + direction);
         scn != NULL;
         scn = elf_getscn(elf->e, inject->sidx + direction + skip)) {
        if (!gelf_getshdr(scn, &shdr)) {
            fprintf(stderr, "Failed to get section header\n");
            return -1;
        }

        if ((direction < 0 && shdr.sh_addr <= inject->shdr.sh_addr) || (direction > 0 && shdr.sh_addr >= inject->shdr.sh_addr)) {
            /* The order is okay from this point on */
            break;
        }

        /* Only reorder code section headers */
        if (shdr.sh_type != SHT_PROGBITS) {
            skip += direction;
            continue;
        }

        /* Swap the injected shdr with its neighbor PROGBITS header */
        if (write_shdr(elf, scn, &inject->shdr, elf_ndxscn(scn)) < 0) {
            return -1;
        }

        if (write_shdr(elf, inject->scn, &shdr, inject->sidx) < 0) {
            return -1;
        }

        inject->sidx += direction + skip;
        inject->scn = elf_getscn(elf->e, inject->sidx);
        skip = 0;
    }

    return 0;
}

int write_secname(elf_data_t *elf, inject_data_t *inject) {
    off_t off;
    size_t n;

    off = lseek(elf->fd, inject->shstroff, SEEK_SET);  // 삽입할 문자열 위치로 이동
    if (off < 0) {
        fprintf(stderr, "lseek failed\n");
        return -1;
    }

    n = write(elf->fd, inject->secname, strlen(inject->secname));  // 섹션 이름 삽입
    if (n != strlen(inject->secname)) {
        fprintf(stderr, "Failed to write section name\n");
        return -1;
    }

    n = strlen(ABITAG_NAME) - strlen(inject->secname);  // 섹션 이름 길이 변경 및 padding
    while (n > 0) {
        if (!write(elf->fd, "\0", 1)) {
            fprintf(stderr, "Failed to write section name\n");
            return -1;
        }
        n--;
    }

    return 0;
}

int rewrite_code_segment(elf_data_t *elf, inject_data_t *inject) {
    // rewrite program header
    inject->phdr.p_type = PT_LOAD;
    inject->phdr.p_offset = inject->off;
    inject->phdr.p_vaddr = inject->secaddr;
    inject->phdr.p_paddr = inject->secaddr;
    inject->phdr.p_filesz = inject->len;
    inject->phdr.p_memsz = inject->len;
    inject->phdr.p_flags = PF_R | PF_X;
    inject->phdr.p_align = 0x1000;

    if (write_phdr(elf, inject) < 0) {
        return -1;
    }
    return 0;
}

int write_phdr(elf_data_t *elf, inject_data_t *inject) {
    off_t off;
    size_t n, phdr_size;
    Elf32_Phdr *phdr_list32;
    Elf64_Phdr *phdr_list64;
    void *phdr_buf;

    if (!gelf_update_phdr(elf->e, inject->pidx, &inject->phdr)) {
        fprintf(stderr, "Failed to update program header\n");
        return -1;
    }

    phdr_buf = NULL;
    if (elf->bits == 32) {
        phdr_list32 = elf32_getphdr(elf->e);
        if (phdr_list32) {
            phdr_buf = &phdr_list32[inject->pidx];
            phdr_size = sizeof(Elf32_Phdr);
        }
    } else {
        phdr_list64 = elf64_getphdr(elf->e);
        if (phdr_list64) {
            phdr_buf = &phdr_list64[inject->pidx];
            phdr_size = sizeof(Elf64_Phdr);
        }
    }
    if (!phdr_buf) {
        fprintf(stderr, "Failed to get program header\n");
        return -1;
    }

    off = lseek(elf->fd, elf->ehdr.e_phoff + inject->pidx * elf->ehdr.e_phentsize, SEEK_SET);
    if (off < 0) {
        fprintf(stderr, "lseek failed\n");
        return -1;
    }

    n = write(elf->fd, phdr_buf, phdr_size);
    if (n != phdr_size) {
        fprintf(stderr, "Failed to write program header\n");
        return -1;
    }

    return 0;
}

int rewrite_entry_point(elf_data_t *elf, inject_data_t *inject) {
    elf->ehdr.e_entry = inject->phdr.p_vaddr + inject->entry;
    return write_ehdr(elf);
}

int write_ehdr(elf_data_t *elf) {
    off_t off;
    size_t n, ehdr_size;
    void *ehdr_buf;

    if (!gelf_update_ehdr(elf->e, &elf->ehdr)) {
        fprintf(stderr, "Failed to update executable header\n");
        return -1;
    }

    if (elf->bits == 32) {
        ehdr_buf = elf32_getehdr(elf->e);
        ehdr_size = sizeof(Elf32_Ehdr);
    } else {
        ehdr_buf = elf64_getehdr(elf->e);
        ehdr_size = sizeof(Elf64_Ehdr);
    }

    if (!ehdr_buf) {
        fprintf(stderr, "Failed to get executable header\n");
        return -1;
    }

    off = lseek(elf->fd, 0, SEEK_SET);
    if (off < 0) {
        fprintf(stderr, "lseek failed\n");
        return -1;
    }

    n = write(elf->fd, ehdr_buf, ehdr_size);
    if (n != ehdr_size) {
        fprintf(stderr, "Failed to write executable header\n");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    FILE *inject_f;
    int elf_fd, ret;
    size_t len, secaddr;
    long entry;
    char *elf_fname, *inject_fname, *secname, *code;
    inject_data_t inject;

    if (argc != 6) {
        printf("Usage: %s <elf> <inject> <name> <addr> <entry>\n\n", argv[0]);
        printf("Inject the file <inject> into the given <elf>, using\n");
        printf("the given <name> and base <addr>. You can optionally specify\n");
        printf("an offset to a new <entry> point (-1 if none)\n");
        return 1;
    }

    elf_fname = argv[1];
    inject_fname = argv[2];
    secname = argv[3];
    secaddr = strtoul(argv[4], NULL, 0);
    entry = strtol(argv[5], NULL, 0);

    inject_f = fopen(inject_fname, "r");
    if (!inject_f) {
        fprintf(stderr, "Failed to open \"%s\"\n", inject_fname);
        return 1;
    }

    fseek(inject_f, 0, SEEK_END);
    len = ftell(inject_f);
    fseek(inject_f, 0, SEEK_SET);

    code = malloc(len);
    if (!code) {
        fprintf(stderr, "Failed to alloc code buffer\n");
        fclose(inject_f);
        return 1;
    }
    if (fread(code, 1, len, inject_f) != len) {
        fprintf(stderr, "Failed to read inject file\n");
        return 1;
    }
    fclose(inject_f);

    elf_fd = open(elf_fname, O_RDWR);
    if (elf_fd < 0) {
        fprintf(stderr, "Failed to open \"%s\"\n", elf_fname);
        free(code);
        return 1;
    }

    inject.code = code;
    inject.len = len;
    inject.entry = entry;
    inject.secname = secname;
    inject.secaddr = secaddr;

    ret = 0;
    ret = inject_code(elf_fd, &inject);

    free(code);
    close(elf_fd);

    return ret;
}