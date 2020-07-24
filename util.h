#pragma once

#include <Windows.h>

namespace util {

    inline DWORD rotl32a(DWORD x, DWORD n)
    {
        return (x << n) | (x >> (32 - n));
    }

    inline char to_lower(char c)
    {
        if (c >= 'A' && c <= 'Z') {
            c = c - 'A' + 'a';
        }
        return c;
    }
};
