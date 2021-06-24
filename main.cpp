#include <Windows.h>
#include <iostream>

#include "classic_antidbg.h"
#include "classic_antivm.h"
#include "neutrino_checks.h"
//#define SINGLE_STEPPING_CHECK

int main()
{
    bool is_detected = false;
    antidbg_timer_check();

    if (exception_is_dbg()) {
        is_detected = true;
        std::cout << "Debugger detected by Exception check!\n";
    }
    if (hardware_bp_is_dbg()) {
        is_detected = true;
        std::cout << "Debugger detected by Hardware Breakpoints!\n";
    }
    if (is_debugger_api()) {
        is_detected = true;
        std::cout << "Debugger detected by API check!\n";
    }
    if (antidbg_timer_check()) {
        is_detected = true;
        std::cout << "Debugger detected by time check!\n";
    }
#ifdef SINGLE_STEPPING_CHECK
    if (is_single_stepping()) {
        is_detected = true;
        std::cout << "Single stepping detected!\n";
    }
#endif

    // Anti-VM
    if (cpuid_bit_check()) {
        std::cout << "VM Detected by CPUID Check!\n";
    }
    if (cpuid_brand_check()) {
        std::cout << "VM Detected by Brand ID!\n";
    }

    if (find_by_neutrino_checks()) {
        is_detected = true;
        std::cout << "Analysis detected by Neutrino set of checks\n";
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
