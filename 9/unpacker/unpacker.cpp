#include "unpacker.h"

void fsize_to_str(unsigned long size, char *buf, unsigned len) {
    int i;
    double d;
    const char *units[] = {"B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};

    i = 0;
    d = (double)size;
    while (d > 1024) {
        d /= 1024;
        i++;
    }

    if (!strcmp(units[i], "B")) {
        snprintf(buf, len, "%.0f%s", d, units[i]);
    } else {
        snprintf(buf, len, "%.1f%s", d, units[i]);
    }
}

void mem_to_file(mem_cluster_t *c, ADDRINT entry) {
    FILE *f;
    char buf[128];

    fsize_to_str(c->size, buf, 128);
    fprintf(logfile, "extracting unpacked region 0x%016jx (%9s) %s%s entry 0x%016jx\n",
            c->base, buf, c->w ? "w" : "-", c->x ? "x" : "-", entry);

    snprintf(buf, sizeof(buf), "unpacked.0x%jx-0x%jx_entry-0x%jx",
             c->base, c->base + c->size, entry);

    f = fopen(buf, "wb");
    if (!f) {
        fprintf(logfile, "failed to open file '%s' for writing\n", buf);
    } else {
        for (ADDRINT i = c->base; i < c->base + c->size; i++) {
            if (fwrite((const void *)&shadow_mem[i].val, 1, 1, f) != 1) {
                fprintf(logfile, "failed to write unpacked byte 0x%jx to file '%s'\n", i, buf);
            }
        }
        fclose(f);
    }
}

void set_cluster(ADDRINT target, mem_cluster_t *c) {
    ADDRINT addr, base;
    unsigned long size;
    bool w, x;
    std::map<ADDRINT, mem_access_t>::iterator i, j;

    j = shadow_mem.find(target);
    assert(j != shadow_mem.end());

    /* scan back to base of cluster */
    base = target;
    w = false;
    x = false;
    for (i = j;; i--) {
        addr = i->first;
        if (addr == base) {
            /* this address is one less than the previous one, so this is still the
             * same cluster */
            if (i->second.w) w = true;
            if (i->second.x) x = true;
            base--;
        } else {
            /* we've reached the start of the cluster but overshot it by one byte */
            base++;
            break;
        }
        if (i == shadow_mem.begin()) {
            base++;
            break;
        }
    }

    /* scan forward to end of cluster */
    size = target - base;
    for (i = j; i != shadow_mem.end(); i++) {
        addr = i->first;
        if (addr == base + size) {
            if (i->second.w) w = true;
            if (i->second.x) x = true;
            size++;
        } else {
            break;
        }
    }

    c->base = base;
    c->size = size;
    c->w = w;
    c->x = x;
}

bool in_cluster(ADDRINT target) {
    mem_cluster_t *c;

    for (unsigned i = 0; i < clusters.size(); i++) {
        c = &clusters[i];
        if (c->base <= target && target < c->base + c->size) {
            return true;
        }
    }

    return false;
}

bool cmp_cluster_size(const mem_cluster_t &c, const mem_cluster_t &d) {
    return c.size > d.size;
}

void print_clusters() {
    ADDRINT addr, base;
    unsigned long size;
    bool w, x;
    unsigned j, n, m;
    char buf[32];
    std::vector<mem_cluster_t> clusters;
    std::map<ADDRINT, mem_access_t>::iterator i;

    /* group shadow_mem into consecutive clusters */
    base = 0;
    size = 0;
    w = false;
    x = false;
    for (i = shadow_mem.begin(); i != shadow_mem.end(); i++) {
        addr = i->first;
        if (addr == base + size) {
            if (i->second.w) w = true;
            if (i->second.x) x = true;
            size++;
        } else {
            if (base > 0) {
                clusters.push_back(mem_cluster_t(base, size, w, x));
            }
            base = addr;
            size = 1;
            w = i->second.w;
            x = i->second.x;
        }
    }

    /* find largest cluster */
    size = 0;
    for (j = 0; j < clusters.size(); j++) {
        if (clusters[j].size > size) {
            size = clusters[j].size;
        }
    }

    /* sort by largest cluster */
    std::sort(clusters.begin(), clusters.end(), cmp_cluster_size);

    /* print cluster bar graph */
    fprintf(logfile, "******* Memory access clusters *******\n");
    for (j = 0; j < clusters.size(); j++) {
        n = ((float)clusters[j].size / size) * 80;
        fsize_to_str(clusters[j].size, buf, 32);
        fprintf(logfile, "0x%016jx (%9s) %s%s: ",
                clusters[j].base, buf,
                clusters[j].w ? "w" : "-", clusters[j].x ? "x" : "-");
        for (m = 0; m < n; m++) {
            fprintf(logfile, "=");
        }
        fprintf(logfile, "\n");
    }
}

void fini(INT32 code /*exit code*/, void *v /*사용자 정의 자료구조*/) {
    print_clusters();  //별다른 계측을 수행하지 않고 Memory cluster들만 출력함
    fprintf(logfile, "------- unpacking complete ---------\n");
    fclose(logfile);
}

void queue_memwrite(ADDRINT addr) {
    saved_addr = addr;
}

void log_memwrite(UINT32 size) {
    ADDRINT addr = saved_addr;
    for (ADDRINT i = addr; i < addr + size; i++) {  //쓰기 작업한 시작한 주소부터 데이터 크기 만큼 바이트 단위로 순회
        shadow_mem[i].w = true;                     //해당 주소에는 쓰기작업가능
        //리턴값 처리 필요
        PIN_SafeCopy(&shadow_mem[i].val /*저장할 공간*/, (const void *)i /*주소*/, 1 /*크기*/);  //해당 주소의 값을 읽어와서 저장한다.
    }
}

void check_indirect_ctransfer(ADDRINT start_address, ADDRINT target) {
    mem_cluster_t c;

    shadow_mem[target].x = true;
    if (shadow_mem[target].w /*target이 이미 명령어에 의해서 기록된 곳으로 제어 흐름 변경이 발생했다면*/
        && !in_cluster(target) /*이미 덤프 작업을 수행하지 않았다면*/) {
        set_cluster(target, &c);  // target Address의 메모리 정보를 c에 dump한다.
        clusters.push_back(c);    // cluster 삽입
        mem_to_file(&c, target);  //파일로 dump 한다.
    }
}

void instrument_mem_cflow(INS ins /*명령어*/, void *v /*사용자 정의 자료구조*/) {
    if(INS_IsMemoryWrite(ins) && INS_MemoryOperandSize(ins, 0) && (INS_MemoryOperandCount(ins) > 0)) {//메모리에 쓰기 작업을 수행 하는지 확인
        INS_InsertPredicatedCall(  //쓰기 작업 주소 등록
            ins /*명령어*/, IPOINT_BEFORE /*메모리 쓰기 작업 이전*/, 
            (AFUNPTR)queue_memwrite /*쓰기 시작 메모리주소 저장*/,
            IARG_MEMORYWRITE_EA /*메모리 기록의 실제 주소*/, 
            IARG_END /*매개변수 끝*/
        );
        //실제 쓰기 작업이후에 어떤 명령어 였는지 조사

        if (INS_HasFallThrough(ins)) {  // fallthrough이면서 메모리 쓰기 작업 명령어인 경우 ; MOV [rbp + 0x40], 0x1234
            INS_InsertPredicatedCall(   // fallthrough인 경우
                ins /*명령어*/, IPOINT_AFTER /*fallthrough인 경우*/, 
                (AFUNPTR)log_memwrite /*분석 루틴*/,
                IARG_MEMORYWRITE_SIZE /*fallthrough 이면서 메모리 쓰기 작업시의 데이터 크기*/, 
                IARG_END /*매개변수 끝*/
            );                                                                                                                 //분석 루틴 삽입 명령어
        }
        if(INS_IsBranch(ins) || INS_IsCall(ins)) {// Branch / call 이면서 메모리 쓰기 작업 명령어인 경우(CMov와같은 conditional move) CMOV [rbp + 0x40], 0x3456
            
            INS_InsertPredicatedCall(
                ins /*명령어*/, IPOINT_TAKEN_BRANCH /*branch taken인 지점*/, 
                (AFUNPTR)log_memwrite /*분석 루틴*/,
                IARG_MEMORYWRITE_SIZE /*매개변수로 전달할 값 : branch taken 이면서 메모리 쓰기 작업시의 데이터 크기*/,
                IARG_END /*명령어 끝*/
            );
        }
    }
    //INS_IsBranch(ins) && INS_IsMemoryRead(ins))
    
    if(INS_IsBranch(ins) && INS_IsMemoryRead(ins) && INS_OperandCount(ins) > 0) {//제어흐름인 경우 : 간접 제어만 하는 이유 : 성능 최적화(일반적으로 패킹 프로그램은 간접 점프로 OEP 도달)
        INS_InsertCall(
            ins /*명령어*/, IPOINT_BEFORE /*간접호출인경우*/, 
            (AFUNPTR)check_indirect_ctransfer /*분석 루틴*/,
            IARG_INST_PTR /*출발지 주소*/, 
            IARG_BRANCH_TARGET_ADDR /*목적지 주소*/, 
            IARG_END /*매개변수 끝*/
        );
    }

}

int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv) != 0) {  // Pin 매개변수 초기화
        fprintf(stderr, "PIN_Init failed\n");
        return 1;
    }
    logfile = fopen(KnobLogFile.Value().c_str(), "a");  // 로그파일 열기
    if (!logfile) {
        fprintf(stderr, "failed to open '%s'\n", KnobLogFile.Value().c_str());
        return 1;
    }
    fprintf(logfile, "------- unpacking binary ---------\n");

    INS_AddInstrumentFunction(instrument_mem_cflow /*계측 루틴*/, NULL /*계측 루틴으로 전달할 매개변수*/);  // 명령어 단위 계측 루틴 등록함수
    PIN_AddFiniFunction(fini /*계측 루틴*/, NULL /*계측 루틴으로 전달할 매개변수*/);                        // fini 함수 계측 루틴 등록 함수
    
    PIN_StartProgram();
    return 1;
}