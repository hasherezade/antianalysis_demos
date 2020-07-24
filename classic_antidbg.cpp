#include "classic_antidbg.h"

#include <iostream>

bool exception_is_dbg()
{
    __try {
        RaiseException(DBG_PRINTEXCEPTION_C, 0, 0, 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        std::cout << "Exception handler executed!\n";
        return false;
    }
    return true;
}

bool is_single_stepping()
{
#ifndef _WIN64
    std::cout << "Trying to set the Trap Flag!\n";
    bool is_exception = false;
    __try
    {
        __asm
        {
            pushfd // push EFLAGS on the stack
            or dword ptr[esp], 0x100 // set the Trap Flag
            popfd // load EFLAGS from the stack
            nop // make one more step
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        std::cout << "Trap generated exception!\n";
        is_exception = true;
    }
    // no exception: single stepping detected!
    return !is_exception;
#else
    std::cerr << __FUNCTION__ << ": Currently not implemented for 64 bit!\n";
    return false;
#endif
}

bool hardware_bp_is_dbg()
{
    CONTEXT ctx = { 0 };
    bool is_hardware_bp = false;

    HANDLE thread = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId());
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(thread, &ctx)) {
        is_hardware_bp = (ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3) != 0;
    }
    CloseHandle(thread);

    return is_hardware_bp;
}

bool is_debugger_api()
{
    if (IsDebuggerPresent()) return true;

    BOOL has_remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &has_remote);

    return has_remote ? true : false;
}

//---
// timer

bool antidbg_timer_check()
{
    static ULONGLONG time = 0;
    if (time == 0) {
        time = __rdtsc();
        std::cout << "First Time: " << std::hex << time << "\n";
        return false;
    }
    ULONGLONG second_time = __rdtsc();
    std::cout << "Second Time: " << std::hex << second_time << "\n";
    ULONGLONG diff = (second_time - time) >> 20;
    std::cout << "Time diff: " << std::hex << diff << "\n";
    if (diff > 0x100) {
        time = second_time;
        return true;
    }
    return false;
}
