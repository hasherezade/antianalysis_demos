#include <Windows.h>
#include <psapi.h>
#include <TlHelp32.h>

#include <iostream>
#include <fstream>
#include <set>

#include "util.h"
#include "neutrino_checks.h"

std::ofstream logFile;

void log_checksum(DWORD checksum, char *name)
{
    std::cout << "[!] " << std::hex << checksum << " : "<< name << std::endl;

    if (!logFile.is_open()) {
        logFile << "[!] " << std::hex << checksum << " : " << name << std::endl;
    }
}

DWORD calc_checksum(char *str, bool enable_tolower)
{
    if (str == NULL) return 0;

    DWORD checksum = 0;
    size_t len = strlen(str);
    for (int i = 0; i < len; i++) {
        checksum = util::rotl32a(checksum, 7);
        char c = str[i];
        if (enable_tolower) {
            c = util::to_lower(c);
        }
        checksum ^= c;
    }
    return checksum;
}

size_t find_denied_processes(std::set<DWORD> &process_list, bool enable_tolower)
{
    size_t found = 0;
    HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    PROCESSENTRY32 process_entry = { 0 };
    process_entry.dwSize = sizeof(process_entry);

    if (!Process32First(hProcessSnapShot, &process_entry)) {
        return 0;
    }

    DWORD checksum = calc_checksum(process_entry.szExeFile, enable_tolower);
    if (process_list.find(checksum) != process_list.end()) {
        log_checksum(checksum, process_entry.szExeFile);
        found++;
    }

    while (Process32Next(hProcessSnapShot, &process_entry)) {
        checksum = calc_checksum(process_entry.szExeFile, enable_tolower);
        if (process_list.find(checksum) != process_list.end()) {
            log_checksum(checksum, process_entry.szExeFile);
            found++;
        }
    }

    // Close the handle
    CloseHandle(hProcessSnapShot);
    return found;
}

size_t find_denied_modules(std::set<DWORD> &modules_list, bool enable_tolower)
{
    size_t found = 0;
    HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, GetCurrentProcessId());
    MODULEENTRY32 module_entry = { 0 };
    module_entry.dwSize = sizeof(module_entry);

    if (!Module32First(hProcessSnapShot, &module_entry)) {
        return 0;
    }

    DWORD checksum = calc_checksum(module_entry.szModule, enable_tolower);
    if (modules_list.find(checksum) != modules_list.end()) {
        found++;
        log_checksum(checksum, module_entry.szModule);
    }

    while (Module32Next(hProcessSnapShot, &module_entry)) {
        checksum = calc_checksum(module_entry.szModule, enable_tolower);
        if (modules_list.find(checksum) != modules_list.end()) {
            found++;
            log_checksum(checksum, module_entry.szModule);
        }
    }

    // Close the handle
    CloseHandle(hProcessSnapShot);
    return found;
}

size_t find_denied_devices(std::set<DWORD> &devs_list)
{
    size_t found = 0;
    char dev[0x20000] = { 0 };
    char dev2[0x2000] = { 0 };
    DWORD res = QueryDosDeviceA(0, dev, 0x20000);

    char* ptr = dev;
    size_t total_len = 0;

    while (total_len < res) {
        DWORD res2 = QueryDosDeviceA(ptr, dev2, sizeof(dev2));
        if (!res2) break;

        DWORD checksum = calc_checksum(ptr, false);
        if (devs_list.find(checksum) != devs_list.end()) {
            log_checksum(checksum, ptr);
            found++;
        }
        size_t len = strlen(ptr) + 1;
        ptr += len;
        total_len += len;
    }
    return found;
}

typedef struct {
    std::set<DWORD> classes_checksums;
    bool hide_found_window;
    size_t found;
} t_class_check_param;

BOOL CALLBACK check_window(HWND hWnd, LPARAM lParam)
{
    t_class_check_param *param = (t_class_check_param*) lParam;
    if (param == nullptr) {
        return FALSE;
    }

    std::set<DWORD> &denied_classes = param->classes_checksums;

    char class_name[MAX_PATH];
    GetClassName(hWnd, class_name, MAX_PATH);

    DWORD checksum = calc_checksum(class_name, true);
    if (denied_classes.find(checksum) != denied_classes.end()) {
        log_checksum(checksum, class_name);
        param->found++;
        if (param->hide_found_window) {
            ShowWindow(hWnd, SW_HIDE);
        }
        else {
            ShowWindow(hWnd, SW_SHOW);
        }
    }
    return TRUE;
}

bool find_by_neutrino_checks(const char *log_filename)
{
    size_t total_found = 0;
    size_t found = 0;

    if (log_filename) {
        logFile.open(log_filename);
    }

    std::set<DWORD> processes_checksums;
    processes_checksums.insert(0x6169078A);
    processes_checksums.insert(0x47000343);
    processes_checksums.insert(0xC608982D);
    processes_checksums.insert(0x46EE4F10);
    processes_checksums.insert(0xF6EC4B30);
    processes_checksums.insert(0xB1CBC652); // VBoxService.exe
    processes_checksums.insert(0x6D3E6FDD); // VBoxTray.exe
    processes_checksums.insert(0x583EB7E8);
    processes_checksums.insert(0xC03EAA65);

    found = find_denied_processes(processes_checksums, false);
    found += find_denied_processes(processes_checksums, true);
    std::cout << "[!] Found suspicious processes: " << found << "\n";
    total_found += found;

    std::set<DWORD> modules_checksums;
    modules_checksums.insert(0x1C669D6A);
    modules_checksums.insert(0xC2F56A18);
    modules_checksums.insert(0x7457D9DD);
    modules_checksums.insert(0xC106E17B);
    modules_checksums.insert(0x5608BCC4);
    modules_checksums.insert(0x6512F9D0);
    modules_checksums.insert(0xC604D52A); // snxhk.dll
    modules_checksums.insert(0x4D0651A5);
    modules_checksums.insert(0xAC12B9FB); // sbiedll.dll
    modules_checksums.insert(0x5B747561);
    modules_checksums.insert(0x53309C85);
    modules_checksums.insert(0xE53ED522);

    found = find_denied_modules(modules_checksums, false);
    found += find_denied_modules(modules_checksums, true);
    std::cout << "[!] Found suspicious modules: " << found << "\n";
    total_found += found;

    std::set<DWORD> devs_checksums;
    devs_checksums.insert(0x642742FF); // VBoxMiniRdrDN
    devs_checksums.insert(0x283CC630); // VBoxGuest
    devs_checksums.insert(0x911E353);
    devs_checksums.insert(0xEDB71E9);
    found = find_denied_devices(devs_checksums);
    std::cout << "[!] Found suspicious devices: " << found << "\n";
    total_found += found;

    t_class_check_param param;
    param.hide_found_window = false;
    param.found = 0;

    param.classes_checksums.insert(0xFE9EA0D5);
    param.classes_checksums.insert(0x6689BB92);
    param.classes_checksums.insert(0x3C5FF312); // procexpl
    param.classes_checksums.insert(0x9B5A88D9); // procmon_window_class
    param.classes_checksums.insert(0x4B4576B5);
    param.classes_checksums.insert(0xAED304FC);
    param.classes_checksums.insert(0x225FD98F);
    param.classes_checksums.insert(0x6D3FA1CA);
    param.classes_checksums.insert(0xCF388E01);
    param.classes_checksums.insert(0xD486D951);
    param.classes_checksums.insert(0x39177889);
    EnumWindows(&check_window, (LPARAM)&param);
    total_found += param.found;

    if (logFile.is_open()) {
        logFile.close();
    }

    return (total_found > 0);
}
