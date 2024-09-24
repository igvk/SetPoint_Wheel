#include <string>
#include <fstream>
#include <iostream>
#include <vector>
#include <algorithm>
#include <cwctype>
#include <shlobj.h>
#include <windows.h>
#include <KnownFolders.h>
#include <TlHelp32.h>

#include "common.hpp"
#include "hooking.hpp"
#include "process.hpp"
#include "utilities.hpp"

#define CONF_DIR L"Logitech\\SetPoint"
#define CONF_FILE L"wheel_apps_list.txt"
#define PROGRAM_NAME L"setpoint-patch.exe"
#define PROGRAM_NAME_STR "setpoint-patch.exe"
#ifdef _WIN64
// TARGET_MACHINE_CODE is the unique byte sequence of target code in procedure to search for
#define TARGET_MACHINE_CODE_ASM \
    0x48, 0x8D, 0x8C, 0x24, 0xE8, 0x0E, 0x00, 0x00, 0xFF, 0x15, 0x52, 0x5C, 0x05, 0x00, 0x48, 0x8D, \
    0x15, 0x7B, 0xEA, 0x08, 0x00, 0x48, 0x8B, 0xC8, 0xFF, 0x15, 0xB2, 0x61, 0x05, 0x00, 0x3B, 0xC7, \
    0x0F, 0x85, 0xF2, 0x01, 0x00, 0x00, 0x48, 0x83, 0x7C, 0x24, 0x40, 0x02, 0x75, 0x5B, 0x48, 0x8D, \
    0x15, 0x13, 0x91, 0x08, 0x00, 0x48, 0x8D, 0x4C, 0x24, 0x78, 0xE8, 0x59, 0xA0, 0xF3, 0xFF, 0x90
// HOOK_CODE_DISP is the offset inside TARGET_MACHINE_CODE where the injected code starts
#define HOOK_CODE_DISP_ASM 0x46 // (code_patch - orig_start)
#define BRANCH_MACHINE_CODE_ASM \
    0xBA, 0x09, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xCF 
#define BRANCH_CODE_DISP_ASM 0x5
// RETURN_CODE_DISP is the offset inside TARGET_MACHINE_CODE where to return back from the hooked function
// (5 bytes minimum offset from HOOK_CODE_DISP)
#define RETURN_CODE_DISP_ASM (HOOK_CODE_DISP_ASM + 0xA)
#define MAX_BRANCH_CODE_DISP 0x100
#else
#define TARGET_MACHINE_CODE 0x0
#define HOOK_MACHINE_CODE 0x0
#define MAX_PATCH_CODE_DISP 0x20
#endif

const byte setpoint_target_code_ASM[] = { TARGET_MACHINE_CODE_ASM };
const size_t setpoint_hook_code_disp_ASM = HOOK_CODE_DISP_ASM;
const size_t setpoint_return_code_disp_ASM = RETURN_CODE_DISP_ASM;
const byte setpoint_branch_code_ASM[] = { BRANCH_MACHINE_CODE_ASM };
const size_t setpoint_branch_code_disp_ASM = BRANCH_CODE_DISP_ASM;
const long code_memory_protection = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

std::vector<std::wstring> enabled_names;
std::vector<std::wstring> disabled_names;

extern "C"
{
    extern void* original_jump_address;
    extern void* original_branch_jump_address;

    extern int target_handler_ASM(const char* name);

    extern void injected_handler_V690();

    __declspec(noinline) int patched_switch_foreground_process_handler(const wchar_t* name)
    {
        DEBUG_TRACE("Patched handler: name = \"%ls\"", name);
        for (auto& glob : disabled_names)
        {
            if (glob_match(name, glob.c_str()))
            {
                DEBUG_TRACE("Patched handler: Matched disabled name \"%ls\"", glob.c_str());
                return -1;
            }
        }
        for (auto& glob : enabled_names)
        {
            if (glob_match(name, glob.c_str()))
            {
                DEBUG_TRACE("Patched handler: Matched enabled name \"%ls\"", glob.c_str());
                return 2;
            }
        }
        return -1;
    }
}

wchar_t* mergeWChar(const wchar_t* dest, const wchar_t* source)
{ 
    const size_t size = (dest ? wcslen(dest) : 0) + wcslen(source) + 1;
    wchar_t* newdest = static_cast<wchar_t*>(malloc(size * sizeof(wchar_t)));
    if (dest)
        wcscpy_s(newdest, size, dest);
    else
        newdest[0] = 0;
    wcscat_s(newdest, size, source);
    return newdest;
}

void read_config()
{
    PWSTR path;
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &path);
    if (SUCCEEDED(hr))
    {
        wchar_t* confpath = mergeWChar(path, L"\\" CONF_DIR L"\\" CONF_FILE);
        DEBUG_TRACE("Config file = %ls", confpath);
        std::wifstream conffile(confpath);
        free(confpath);
        if (conffile)
        {
            std::wstring line;
            while (std::getline(conffile, line))
            {
                if (line.empty())
                    continue;
                std::transform(
                    line.begin(),
                    line.end(),
                    line.begin(),
                    [](const wchar_t c) { return std::towlower(c); }
                );
                switch (line[0])
                {
                case ';':
                    continue;
                case '-':
                    disabled_names.emplace_back(line.substr(1));
                    break;
                default:
                    enabled_names.emplace_back(line);
                    break;
                }
            }
            std::wstring program_name(PROGRAM_NAME);

            enabled_names.emplace_back(program_name);
            enabled_names.shrink_to_fit();
            disabled_names.shrink_to_fit();
        }
    }
    else
    {
        DEBUG_TRACE("Config directory not found: error = %lux", hr);
    }
}

DWORD get_proc_id(const wchar_t* procName)
{
    PROCESSENTRY32 procEntry;
    procEntry.dwSize = sizeof procEntry;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hSnap == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32First(hSnap, &procEntry))
    {
        do
        {
            if (!_wcsicmp(procEntry.szExeFile, procName))
            {
                CloseHandle(hSnap);
                return procEntry.th32ProcessID;
            }
        } while (Process32Next(hSnap, &procEntry));
    }
    CloseHandle(hSnap);
    return 0;
}

bool find_data(byte* memory, size_t size, const byte* pattern, size_t length, byte*& data)
{
    if (size >= length)
    {
        const byte* last_byte = memory + size - length;
        for (; memory <= last_byte; memory++)
        {
            if (!memcmp(memory, pattern, length))
            {
                data = memory;
                return true;
            }
        }
    }
    data = nullptr;
    return false;
}

void hook_current_process()
{
    const wchar_t setpoint_process_name[] = PROGRAM_NAME;
    WCHAR exePath[MAX_PATH + 1];
    DWORD exePathLen = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    if (exePathLen == 0)
    {
        DEBUG_TRACE("GetModuleFileName: error = %lux", GetLastError());
    }
    else
    {
        DEBUG_TRACE("Exe path is %ls", exePath);
        const size_t processNameLen = wcsnlen(setpoint_process_name, MAX_PATH);
        if (exePathLen >= processNameLen && wcsncmp(exePath + exePathLen - processNameLen, setpoint_process_name, MAX_PATH) == 0)
        {
            /*
            SYSTEM_INFO sys_info;
            GetSystemInfo(&sys_info);
            */

            MEMORY_BASIC_INFORMATION mbi;

            for (byte* addr = nullptr; VirtualQuery(addr, &mbi, sizeof mbi); addr += mbi.RegionSize)
            {
                if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && (mbi.Protect & code_memory_protection) != 0)
                {
                    byte* memory = static_cast<byte*>(mbi.BaseAddress);
                    size_t bytes_count = mbi.RegionSize;

                    void (*injected_handler)();
                    byte *found_addr, *hook_address;
                    size_t target_code_size, hook_code_size;
                    if (find_data(memory, bytes_count, setpoint_target_code_ASM, target_code_size = sizeof setpoint_target_code_ASM, found_addr))
                    {
                        DEBUG_TRACE("Found pattern at %p", found_addr);
                        injected_handler = injected_handler_V690;
                        hook_address = found_addr + setpoint_hook_code_disp_ASM;
                        hook_code_size = setpoint_return_code_disp_ASM - setpoint_hook_code_disp_ASM;
                        original_jump_address = found_addr + setpoint_return_code_disp_ASM;

                        found_addr += target_code_size;
                        size_t count = bytes_count - (found_addr - memory);
                        if (count > MAX_BRANCH_CODE_DISP)
                            count = MAX_BRANCH_CODE_DISP;
                        if (find_data(found_addr, count, setpoint_branch_code_ASM, sizeof setpoint_branch_code_ASM, found_addr))
                        {
                            DEBUG_TRACE("Found branch code at %p", found_addr);
                            original_branch_jump_address = found_addr + setpoint_branch_code_disp_ASM;
                        }
                        else
                        {
                            DEBUG_TRACE("Branch code not found");
                            continue;
                        }
                    }
                    else
                        continue;

                    unsigned long oldProtect;
                    if (!VirtualProtect(addr, bytes_count, PAGE_EXECUTE_READWRITE, &oldProtect))
                    {
                        DEBUG_TRACE("VirtualProtectEx: error = %lux", GetLastError());
                        break;
                    }

                    SetOtherThreadsSuspended(true);
                    const bool result = InstallAllocateHook(hook_address, hook_code_size, injected_handler);
                    SetOtherThreadsSuspended(false);

                    VirtualProtect(addr, bytes_count, oldProtect, &oldProtect);
                    if (result)
                        DEBUG_TRACE("Injected code at %p", hook_address);
                    else
                        DEBUG_TRACE("Unable to inject code at %p", hook_address);

                    return;
                }
            }
            DEBUG_TRACE("Code was not modified");
        }
    }
}

int main()
{
    read_config();
    hook_current_process();
    const int result = target_handler_ASM(PROGRAM_NAME_STR);
    std::cout << "Handler result = " << result << '\n';
    return 0;
}
