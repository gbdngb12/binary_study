#include <stdint.h>
#include <bfd.h>
#include <string>
#include <vector>

class Binary;
class Section;
class Symbol;

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

/**
 * @brief 바이너리파일을 Binary 클래스에 로드한다.
 * @param fname 바이너리 파일 상대/절대 경로
 * @param bin 바이너리 클래스 포인터
 * @param type 바이너리 타입
 * @return -1 : 오류 / 0 성공
*/
int load_binary(std::string &fname, Binary *bin, Binary::BinaryType type);
/**
 * @brief Binary 클래스의 동적 정보를 모두 해제한다.
 * @param bin 바이너리 클래스 포인터
*/
void unload_binary(Binary *bin);
/**
 * @brief load_binary 함수는 복잡한 과정을 수반하므로 실제적으로 bfd 라이브러리를 이용해 Binary 클래스에 매핑하는 함수
 * @param fname 바이너리 파일 상대/절대 경로
 * @param bin 바이너리 클래스 포인터
 * @param type 바이너리 타입
 * @return -1 : 오류 / 0 성공
*/
static int load_binary_bfd(std::string &fname, Binary *bin, Binary::BinaryType type);
/**
 * @brief Binary의 모든 section들을 로드한다. 
 * @param bfd_h bfd handler pointer
 * @param bin 바이너리 클래스 포인터
 * @return -1 : 오류 / 0 성공
*/
static int load_sections_bfd(bfd *bfd_h, Binary *bin);
/**
 * @brief Binary의 모든 동적 심벌을 로드한다.
 * @param bfd_h bfd handler pointer
 * @param bin 바이너리 클래스 포인터
 * @return -1 : 오류 / 0 성공
*/
static int load_dynsym_bfd(bfd *bfd_h, Binary *bin);
/**
 * @brief  바이너리 파일의 정적 심벌을 모두 로드한다.
 * @param bfd_h bfd handler pointer
 * @param bin Binary 클래스 포인터
 * @return -1 : 오류 / 0 성공
*/
static int load_symbols_bfd(bfd *bfd_h, Binary *bin);
/**
 * @brief bfd 라이브러리를 이용해 바이너리 파일을 여는 일련의 과정을 수행한다.
 * @param fname 바이너리 파일의 상대/절대 경로
 * @return 성공 : bfd handler / 실패 NULL
*/
static bfd *open_bfd(std::string &fname);