#include "procmon_check.h"
#include <fltuser.h>

static NTSTATUS is_procmon_sc_registered(const wchar_t* service_name, const size_t service_name_size);

static HRESULT tryopen_procmon_sc(const wchar_t* service_name);

static BOOL do_is_procmon_present(const wchar_t* service_name, const size_t service_name_size);

static NTSTATUS is_procmon_sc_registered(const wchar_t* service_name, const size_t service_name_size) {
    HKEY hk;
    wchar_t w_subkey[1024] = L"";
    wcsncpy_s(w_subkey, sizeof(w_subkey) / sizeof(w_subkey[0])  - 2, L"System\\CurrentControlSet\\Services\\",
              wcslen(L"System\\CurrentControlSet\\Services\\"));
    wcsncat_s(w_subkey, sizeof(w_subkey) / sizeof(w_subkey[0]) - 2, service_name, service_name_size);
    NTSTATUS retval = RegOpenKeyExW(HKEY_LOCAL_MACHINE, w_subkey, 0, KEY_QUERY_VALUE, &hk);
    if (retval == ERROR_SUCCESS) {
        RegCloseKey(hk);
    }
    return retval;
}

static HRESULT tryopen_procmon_sc(const wchar_t* service_name) {
    HFILTER filter;
    HRESULT res = FilterCreate(service_name, &filter);
    if (res == S_OK) {
        FilterClose(filter);
    }
    return res;
}

static BOOL do_is_procmon_present(const wchar_t* service_name, const size_t service_name_size) {
    HRESULT res = tryopen_procmon_sc(service_name);
    switch (res) {
        case S_OK:
            return TRUE;

        case E_ACCESSDENIED:
            return (is_procmon_sc_registered(service_name, service_name_size) == ERROR_SUCCESS);
    }
    return FALSE;
}

BOOL is_procmon_sc_present(void) {
    static const wchar_t* procmon_scs[] = {
        L"PROCMON24",
        L"PROCMON23",
    };
    static const size_t procmon_scs_nr = sizeof(procmon_scs) / sizeof(procmon_scs[0]);
    const wchar_t** service = &procmon_scs[0];
    const wchar_t** service_end = service + procmon_scs_nr;
    BOOL is = FALSE;
    while (!is && service != service_end) {
        is = do_is_procmon_present(*service, wcslen(*service));
        service++;
    }
    return is;
}
