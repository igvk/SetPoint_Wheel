#include <mutex>            // std::{once_flag, call_once}
#include <string>
#include <fstream>
#include <vector>
#include <algorithm>
#include <cwctype>
#include <shlobj.h>
#include <windows.h>
#include <KnownFolders.h>
#include <TlHelp32.h>

#include "common.hpp"
#include "version_dll.hpp"

#include "hooking.hpp"
#include "process.hpp"
#include "utilities.hpp"

#define CONF_DIR L"Logitech\\SetPoint"
#define CONF_FILE L"wheel_apps_list.txt"
#define PROGRAM_NAME L"SetPoint.exe"
#ifdef _WIN64
// TARGET_MACHINE_CODE is the unique byte sequence of target code in procedure to search for
#define TARGET_MACHINE_CODE_V690 \
    0x48, 0x8D, 0x8C, 0x24, 0xE8, 0x0E, 0x00, 0x00, 0xFF, 0x15, 0x52, 0x5C, 0x05, 0x00, 0x48, 0x8D, \
    0x15, 0x7B, 0xEA, 0x08, 0x00, 0x48, 0x8B, 0xC8, 0xFF, 0x15, 0xB2, 0x61, 0x05, 0x00, 0x3B, 0xC7, \
    0x0F, 0x85, 0xF2, 0x01, 0x00, 0x00, 0x48, 0x83, 0x7C, 0x24, 0x40, 0x02, 0x75, 0x5B, 0x48, 0x8D, \
    0x15, 0x13, 0x91, 0x08, 0x00, 0x48, 0x8D, 0x4C, 0x24, 0x78, 0xE8, 0x59, 0xA0, 0xF3, 0xFF, 0x90
#define BRANCH_MACHINE_CODE_V690 \
    0xBA, 0x09, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xCE
#define BRANCH_CODE_DISP_V690 0x5
// HOOK_CODE_DISP is the offset inside TARGET_MACHINE_CODE where the injected code starts
#define HOOK_CODE_DISP_V690 0xE
// RETURN_CODE_DISP is the offset inside TARGET_MACHINE_CODE where to return back from the hooked function
// (5 bytes minimum offset from HOOK_CODE_DISP)
#define RETURN_CODE_DISP_V690 (HOOK_CODE_DISP_V690 + 0xA)
#define MAX_BRANCH_CODE_DISP 0x100
#else
#endif

const wchar_t setpoint_process_name[] = PROGRAM_NAME;
const byte setpoint_target_code_V690[] = { TARGET_MACHINE_CODE_V690 };
const size_t setpoint_hook_code_disp_V690 = HOOK_CODE_DISP_V690;
const size_t setpoint_return_code_disp_V690 = RETURN_CODE_DISP_V690;
const byte setpoint_branch_code_V690[] = { BRANCH_MACHINE_CODE_V690 };
const size_t setpoint_branch_code_disp_V690 = BRANCH_CODE_DISP_V690;
const long code_memory_protection = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

unsigned int module_patch_check = 3;

std::vector<std::wstring> enabled_names;
std::vector<std::wstring> disabled_names;

extern "C"
{
    extern void* original_jump_address;
    extern void* original_branch_jump_address;

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

namespace
{
    bool isWin64()
    {
#if defined(_WIN64)
        DEBUG_TRACE(L"isWin64 : _WIN64");
        return true;
#else
        DEBUG_TRACE(L"isWin64 : _WIN32");
        BOOL wow64Process = FALSE;
        return (IsWow64Process(GetCurrentProcess(), &wow64Process) != 0) && (wow64Process != 0);
#endif
    }

    DllType determineDllType(const wchar_t* dllFilename)
    {
        return DllType::Version;
    }

    void loadGenuineDll(DllType dllType, const wchar_t* systemDirectory)
    {
        switch(dllType)
        {
        case DllType::Version:
            version_dll::loadGenuineDll(systemDirectory);
            break;
        default:
            break;
        }
    }

    void unloadGenuineDll(DllType dllType)
    {
        switch (dllType)
        {
        case DllType::Version:
            version_dll::unloadGenuineDll();
            break;
        default:
            break;
        }
    }
}


namespace
{
    DllType dllType = DllType::Unknown;

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

    wchar_t* mergeWChar(wchar_t* dest, const wchar_t* source)
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
                enabled_names.shrink_to_fit();
                disabled_names.shrink_to_fit();
            }
        }
        else
        {
            DEBUG_TRACE("Config directory not found: error = %lux", hr);
        }
    }

    void patch_mem()
    {
        // limit number of attempts to patch
        if (module_patch_check == 0)
            return;
        --module_patch_check;

        DEBUG_TRACE("patch_mem [%d]", module_patch_check);

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
                MEMORY_BASIC_INFORMATION mbi;

                for (byte* addr = nullptr; VirtualQuery(addr, &mbi, sizeof mbi); addr += mbi.RegionSize)
                {
                    if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && (mbi.Protect & code_memory_protection) != 0)
                    {
                        byte* memory = static_cast<byte*>(mbi.BaseAddress);
                        size_t bytes_count = mbi.RegionSize;

                        void (*injected_handler)();
                        byte* found_addr, * hook_address;
                        size_t target_code_size, hook_code_size;
                        if (find_data(memory, bytes_count, setpoint_target_code_V690, target_code_size = sizeof setpoint_target_code_V690, found_addr))
                        {
                            DEBUG_TRACE("Found pattern at %p", found_addr);
                            injected_handler = injected_handler_V690;
                            hook_address = found_addr + setpoint_hook_code_disp_V690;
                            hook_code_size = setpoint_return_code_disp_V690 - setpoint_hook_code_disp_V690;
                            original_jump_address = found_addr + setpoint_return_code_disp_V690;

                            found_addr += target_code_size;
                            size_t count = bytes_count - (found_addr - memory);
                            if (count > MAX_BRANCH_CODE_DISP)
                                count = MAX_BRANCH_CODE_DISP;
                            if (find_data(found_addr, count, setpoint_branch_code_V690, sizeof setpoint_branch_code_V690, found_addr))
                            {
                                DEBUG_TRACE("Found branch code at %p", found_addr);
                                original_branch_jump_address = found_addr + setpoint_branch_code_disp_V690;
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

    void init(HMODULE hModule) {
        DEBUG_TRACE(L"init : begin");

        wchar_t systemDirectory[MAX_PATH + 1];
        const auto w64 = isWin64();
        DEBUG_TRACE(L"init : isWin64=%d", w64);
        if (w64)
            GetSystemDirectoryW(systemDirectory, MAX_PATH);
        else
            GetSystemWow64DirectoryW(systemDirectory, MAX_PATH);
        DEBUG_TRACE(L"init : systemDirectory=\"%s\"", systemDirectory);

        {
            wchar_t moduleFullpathFilename[MAX_PATH + 1];
            GetModuleFileNameW(hModule, moduleFullpathFilename, MAX_PATH);
            DEBUG_TRACE(L"init : moduleFullpathFilename=\"%s\"", moduleFullpathFilename);

            wchar_t fname[_MAX_FNAME + 1];
            wchar_t drive[_MAX_DRIVE + 1];
            wchar_t dir[_MAX_DIR + 1];
            wchar_t ext[_MAX_EXT + 1];
            _wsplitpath_s(moduleFullpathFilename, drive, dir, fname, ext);
            DEBUG_TRACE(L"init : fname=\"%s\"", fname);

            dllType = determineDllType(fname);
            DEBUG_TRACE(L"init : dllType=%d", dllType);
        }

        loadGenuineDll(dllType, systemDirectory);

        read_config();

        DEBUG_TRACE(L"init : end");
    }

    void cleanup()
    {
        DEBUG_TRACE(L"cleanup : begin");

        unloadGenuineDll(dllType);
        DEBUG_TRACE(L"cleanup : end");
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
{
    static std::once_flag initFlag;
    static std::once_flag cleanupFlag;

    switch(ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DEBUG_TRACE(L"DLL_PROCESS_ATTACH (hModule=%p) : begin", hModule);
        std::call_once(initFlag, [&]() { init(hModule); });
        DEBUG_TRACE(L"DLL_PROCESS_ATTACH (hModule=%p) : end", hModule);
        break;

    case DLL_PROCESS_DETACH:
        DEBUG_TRACE(L"DLL_PROCESS_DETACH (hModule=%p) : begin", hModule);
        std::call_once(cleanupFlag, [&]() { cleanup(); });
        DEBUG_TRACE(L"DLL_PROCESS_DETACH (hModule=%p) : end", hModule);
        break;

    case DLL_THREAD_ATTACH:
        if (module_patch_check)
            patch_mem();
        break;

    case DLL_THREAD_DETACH:
    default:
        break;
    }

    return TRUE;
}
