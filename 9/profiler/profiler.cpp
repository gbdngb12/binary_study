#include "profiler.h"

void count_bb_insns(UINT32 n /*블록내의 명령어의 수*/) {
    insn_count += n;
}

void count_cflow(ADDRINT start_address, ADDRINT target) {
    cflows[target][start_address]++;
    cflow_count++;
}

void count_call(ADDRINT start_address, ADDRINT target) {
    calls[target][start_address]++;
    call_count++;
}

void log_syscall(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
    syscalls[PIN_GetSyscallNumber(ctxt, std)]++;
    syscall_count++;
}

void print_usage() {
    std::string help = KNOB_BASE::StringKnobSummary();

    fprintf(stderr, "\nProfile call and jump targets\n");
    fprintf(stderr, "%s\n", help.c_str());
}

void print_results(INT32 code, void *v) {
    ADDRINT ip, target;
    unsigned long count;
    std::map<ADDRINT, std::map<ADDRINT, unsigned long>>::iterator i;
    std::map<ADDRINT, unsigned long>::iterator j;

    printf("executed %lu instructions\n\n", insn_count);

    printf("******* CONTROL TRANSFERS *******\n");
    for (i = cflows.begin(); i != cflows.end(); i++) {
        target = i->first;
        for (j = i->second.begin(); j != i->second.end(); j++) {
            ip = j->first;
            count = j->second;
            printf("0x%08jx <- 0x%08jx: %3lu (%0.2f%%)\n",
                   target, ip, count, (double)count / cflow_count * 100.0);
        }
    }

    if (!calls.empty()) {
        printf("\n******* FUNCTION CALLS *******\n");
        for (i = calls.begin(); i != calls.end(); i++) {
            target = i->first;

            for (j = i->second.begin(); j != i->second.end(); j++) {
                ip = j->first;
                count = j->second;
                printf("[%-30s] 0x%08jx <- 0x%08jx: %3lu (%0.2f%%)\n",
                       funcnames[target].c_str(), target, ip, count, (double)count / call_count * 100.0);
            }
        }
    }

    if (!syscalls.empty()) {
        printf("\n******* SYSCALLS *******\n");
        for (j = syscalls.begin(); j != syscalls.end(); j++) {
            count = j->second;
            printf("%3ju: %3lu (%0.2f%%)\n", j->first, count, (double)count / syscall_count * 100.0);
        }
    }
}

void parse_funcsyms(IMG img, void *v) {
    if (!IMG_Valid(img)) return; /** 이미지의 유효성 판단*/

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {     /** Image내의 모든 Section 순회*/
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) { /** Section내의 모든 routine(함수) 순회*/
            funcnames[RTN_Address(rtn)] = RTN_Name(rtn);
        }
    }
}

void instrument_trace(TRACE trace, void *v) {
    /**
     * 현재 trace가 올바른 위치에 존재하는 Image인지 확인
     */
    IMG img = IMG_FindByAddress(TRACE_Address(trace)); /** 현재 trace의 이미지를 가져온다.*/
    // 현재 trace의 Image가 동적 라이브러리나 고유 라이브러리를 제외한 부분일때에만 이미지 계측
    if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) return; /** 즉, Only for 대상 어플리케이션*/

    /**
     * 올바른 image에 있는 trace의 모든 block을 순회한다
     */
    for (BBL bb = TRACE_BblHead(trace); BBL_Valid(bb); bb = BBL_Next(bb)) {
        instrument_bb(bb); /** 블록단위 분석 루틴 콜백 설치 함수 호출*/
    }
}

void instrument_bb(BBL bb) {
    BBL_InsertCall(bb, IPOINT_ANYWHERE /*분석 콜백 설치시 pin이 자동으로 최적화*/,
                   (AFUNPTR)count_bb_insns /*분석 루틴*/,
                   IARG_UINT32 /*매개변수 타입*/, BBL_NumIns(bb) /*블록내의 명령어 수(매개변수)*/,
                   IARG_END /*매개변수 끝*/); /** @brief 분석 루틴 콜백 설치*/
}

void instrument_insn(INS ins, void *v) {
    if (!(INS_IsBranch(ins) || INS_IsCall(ins))) return; /** branch나 call이 아니면 계측 x*/

    IMG img = IMG_FindByAddress(INS_Address(ins));
    // 현재 Image가 동적 라이브러리나 고유 라이브러리를 제외한 부분일때에만 이미지 계측
    if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) return; /** 즉, Only for 대상 어플리케이션*/

    INS_InsertPredicatedCall(
        ins /*명령어*/, IPOINT_TAKEN_BRANCH /*taken일때 호출*/,
        (AFUNPTR)count_cflow /*분석 루틴*/,
        IARG_INST_PTR /*taken이 발생한 시점의 주소*/,
        IARG_BRANCH_TARGET_ADDR /*taken target 주소*/,
        IARG_END /* 매개변수 끝*/); /** taken일때 콜백 삽입*/

    if (INS_HasFallThrough(ins)) {  // fallthrough인경우의 콜백 삽입
        INS_InsertPredicatedCall(
            ins /*명령어*/, IPOINT_AFTER /*fallthrough이후의 지점*/,
            (AFUNPTR)count_cflow, /*분석 루틴*/
            IARG_INST_PTR /*fallthrough가 발생한 시작 지점의 주소*/,
            IARG_FALLTHROUGH_ADDR /*fallthrough 목적지 지점*/,
            IARG_END); /*fallthrough일때 콜백 삽입*/
    }

    if (INS_IsCall(ins)) {  // 현재 명령어가 함수 호출인 경우
        if (ProfileCalls.Value()) {
            INS_InsertCall(
                ins/*명령어*/, IPOINT_BEFORE/*함수 호출 이전에 삽입*/
                , (AFUNPTR)count_call,/*분석 루틴*/
                IARG_INST_PTR/*call이 발생한 시작지점의 주소*/,
                IARG_BRANCH_TARGET_ADDR,/*branch taken 목적지 주소*/
                IARG_END/*매개변수 끝*/); /*call 명령어발생 했을때 콜백 삽입*/
        }
    }
}

int main(int argc, char *argv[]) {
    PIN_InitSymbols();          /** (존재 한다면)Symbol 정보를 읽기위한 작업*/
    if (PIN_Init(argc, argv)) { /** PIN_InitSymbols함수를 제외한 모든 PIN 함수보다 선행호출 되야함 커맨드 라인 옵션까지 모두 설정해줌*/
        print_usage();
        return 1;
    }
    IMG_AddInstrumentFunction(parse_funcsyms /*분석 루틴*/, NULL /*분석루틴 실행시 전달 할 자료구조*/);      // 이미지단위 분석루틴 등록 함수
    INS_AddInstrumentFunction(instrument_insn /*계측 루틴*/, NULL /*계측루틴 실행시 전달 할 자료구조*/);     // 명령어단위 계측루틴 등록 함수
    TRACE_AddInstrumentFunction(instrument_trace /*계측 루틴*/, NULL /*계측루틴 실행시 전달 할 자료구조*/);  // trace단위(블록과 비슷함) 계측루틴 등록 함수
    if (ProfileSysCalls.Value()) {                                                                            // profile Systemcall의 옵션이 주어졌다면
        PIN_AddSyscallEntryFunction(log_syscall /*분석 루틴*/, NULL /*분석루틴 실행시 전달 할 자료구조*/);   // system call 호출되기 전 log_syscall 분석 루틴 등록 함수
        // PIN_AddSyscallExitFunction(); system call이 호출된후 계측 루틴 등록 함수
    }
    // 일부 프로그램에서 정상적으로 종료되지 않는경우 fini함수가 안정적으로 호출되지 않는 경우가 있음
    PIN_AddFiniFunction(print_results /*루틴*/, NULL /*계측루틴 실행시 전달 할 자료구조*/);  // 어플리케이션이 종료되거나 Pin의 제어가 종료되는 시점에 print_results 계측 루틴 등록 함수

    PIN_StartProgram();  // 어플리케이션 실행 -> 에뮬레이션 시작

    return 0;  // 절대로 수행되지 않는다.
}