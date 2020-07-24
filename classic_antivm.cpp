#include "classic_antivm.h"

#include <string>
#include <set>
#include <iostream>

bool cpuid_bit_check()
{
#ifndef _WIN64
    bool is_bit_set = false;
    __asm {
        mov eax, 1
        cpuid
        bt  ecx, 0x1f
        jnc  finish
        mov is_bit_set, 1
        finish:
    }
    std::cout << "Is VM bit set? " << is_bit_set << "\n";
    return is_bit_set;
#endif
    std::cerr << __FUNCTION__ << ": Currently not implemented for 64 bit!\n";
    return false;
}

bool _cpuid_brand_check(std::set<std::string> &vm_brands)
{
#ifndef _WIN64
    bool is_vm_brand = false;
    char brand_str[sizeof(DWORD) * 4] = { 0 };

    DWORD v0, v1, v2;
    v0 = v1 = v2  = 0;
 
    __asm {
        mov eax, 0x40000000
        cpuid
        mov v0, ebx
        mov v1, ecx
        mov v2, edx
    }

    memcpy(brand_str, &v0, sizeof(DWORD));
    memcpy(brand_str + sizeof(DWORD), &v1, sizeof(DWORD));
    memcpy(brand_str + sizeof(DWORD) * 2, &v2, sizeof(DWORD));

    char *ptr = (char*)brand_str;
    std::cout << "BrandID: " << ptr << "\n";
    if (vm_brands.find(brand_str) != vm_brands.end()) {
        return true;
    }
    return false;
#endif
    std::cerr << __FUNCTION__ << ": Currently not implemented for 64 bit!\n";
    return false;
}

bool cpuid_brand_check()
{
    std::set<std::string> vm_brands;
    vm_brands.insert("KVMKVMKVM");
    vm_brands.insert("VMwareVMware");
    vm_brands.insert("XenVMMXenVMM");
    vm_brands.insert("VBoxVBoxVBox");
    vm_brands.insert("Microsoft Hv");

    return _cpuid_brand_check(vm_brands);
}
