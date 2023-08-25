#include <Windows.h>
#include <iostream>

#include "classic_antidbg.h"
#include "classic_antivm.h"
#include "neutrino_checks.h"
#include "kernelmode_antidbg.h"
#include "procmon_check.h"
#include "ntdll_undoc.h"

//#define SINGLE_STEPPING_CHECK

int main();

bool checkProcessDebugFlags()
{
    // ProcessDebugFlags
    const int ProcessDebugFlags = 0x1f;
    auto _NtQueryInformationProcess = reinterpret_cast<decltype(&NtQueryInformationProcess)>(GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess"));
    // Other Vars
    NTSTATUS Status;
    DWORD NoDebugInherit = 0;

    Status = _NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugFlags, &NoDebugInherit, sizeof(DWORD), NULL);
    std::cout << "ProcessDebugFlags: " << std::hex << NoDebugInherit << "\n";
    
    return (Status == 0 && NoDebugInherit == 0) ? true : false;
}

bool clearProcessDebugFlags()
{
    // ProcessDebugFlags
    const int ProcessDebugFlags = 0x1f;

    auto _NtSetInformationProcess = reinterpret_cast<decltype(&NtSetInformationProcess)>(GetProcAddress(GetModuleHandleA("ntdll"), "NtSetInformationProcess"));
    // Other Vars
    NTSTATUS Status;
    DWORD NoDebugInherit = 1;

    Status = _NtSetInformationProcess(GetCurrentProcess(), ProcessDebugFlags, &NoDebugInherit, sizeof(DWORD));
    return (Status == 0);
}

#ifndef _WIN64
bool exec_int2d()
{
    __try
    {
        __asm xor eax, eax;
        __asm int 0x2d;
        __asm nop;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}
#endif

// from: https://anti-debug.checkpoint.com/techniques/process-memory.html#anti-step-over
bool CheckForSpecificByte(BYTE cByte, PVOID pMemory, SIZE_T nMemorySize = 0)
{
    PBYTE pBytes = (PBYTE)pMemory;
    for (SIZE_T i = 0; ; i++)
    {
        // Break on RET (0xC3) if we don't know the function's size
        if (((nMemorySize > 0) && (i >= nMemorySize)) ||
            ((nMemorySize == 0) && (pBytes[i] == 0xC3)))
            break;

        if (pBytes[i] == cByte)
            return true;
    }
    return false;
}

bool IsCCSet()
{
    PVOID functionsToCheck[] = {
        &main
    };
    for (auto funcAddr : functionsToCheck)
    {
        if (CheckForSpecificByte(0xCC, funcAddr))
            return true;
    }
    return false;
}

int main()
{
    if (clearProcessDebugFlags()) {
        std::cout << "Flag cleared!\n";
    }
    IsCCSet();
#ifndef _WIN64
    exec_int2d();
#endif
    bool is_detected = false;
    antidbg_timer_check();
    if (checkProcessDebugFlags()) {
        is_detected = true;
        std::cout << "[*] Debugger detected by ProcessDebugFlags!\n";
    }
    if (exception_is_dbg()) {
        is_detected = true;
        std::cout << "[*] Debugger detected by Exception check!\n";
    }
    if (hardware_bp_is_dbg()) {
        is_detected = true;
        std::cout << "[*] Debugger detected by Hardware Breakpoints!\n";
    }
    if (is_debugger_api()) {
        is_detected = true;
        std::cout << "[*] Debugger detected by API check!\n";
    }
    if (antidbg_timer_check()) {
        is_detected = true;
        std::cout << "[*] Debugger detected by time check!\n";
    }
#ifdef SINGLE_STEPPING_CHECK
    if (is_single_stepping()) {
        is_detected = true;
        std::cout << "Single stepping detected!\n";
    }
#endif

    // Anti-VM
    if (cpuid_bit_check()) {
        std::cout << "[*] VM Detected by CPUID Check!\n";
    }
    if (cpuid_brand_check()) {
        std::cout << "[*] VM Detected by Brand ID!\n";
    }

    if (find_by_neutrino_checks()) {
        is_detected = true;
        std::cout << "[*] Analysis detected by Neutrino set of checks\n";
    }
    t_kdb_mode kdb_mode = is_kernelmode_dbg_enabled();
    if (kdb_mode == KDB_LOCAL_ENABLED || kdb_mode == KDB_REMOTE_ENABLED) {
        is_detected = true;
        std::cout << "[*] Kernelmode debugging enabled!\n";
    }
    if (is_procmon_sc_present()) {
        is_detected = true;
        std::cout << "[*] ProcMon service is present!\n";
    }
    if (is_detected) {
        MessageBoxA(NULL, "Analysis environment detected!", "Detected", MB_ICONEXCLAMATION | MB_OK);
    }
    else {
        MessageBoxA(NULL, "No analysis environment detected!", "Not Detected", MB_ICONINFORMATION | MB_OK);
    }
    system("pause");
    return 0;
}
