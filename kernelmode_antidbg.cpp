#include "kernelmode_antidbg.h"

#include <iostream>

#define KUSER_SHARED_VA 0x7FFE0000
#define KUSER_SHARED_SIZE 0x3B8

inline bool is_kuser_shared_mapped()
{
    if (IsBadReadPtr((BYTE*)KUSER_SHARED_VA, KUSER_SHARED_SIZE)) {
        std::cerr << "KDB: Failed to retrieve KUSER_SHARED_DATA\n";
        return false;
    }
    return true;
}

// from Hidden Bee malware:
bool is_kernelmode_dbg_enabled()
{
    const ULONGLONG KdDebuggerEnable_offset = 0x2d4;
    if (!is_kuser_shared_mapped()) {
        return false;
    }
    BYTE *KdDebuggerEnable = (BYTE*)(KUSER_SHARED_VA + KdDebuggerEnable_offset);
    if (*KdDebuggerEnable) {
        /* 
        this flag is selected if:
        bcdedit /debug on
        */
        std::cout << "KDB: Enabled!\n";
        return true;
    }
    std::cout << "KDB: Disabled\n";
    return false;
}
