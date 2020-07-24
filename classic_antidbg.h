#pragma once

#include <Windows.h>

bool exception_is_dbg();
bool hardware_bp_is_dbg();
bool is_debugger_api();
bool antidbg_timer_check();
bool is_single_stepping();
