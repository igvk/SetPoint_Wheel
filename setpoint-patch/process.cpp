#include <cstdint>
#include <thread>
#include <windows.h>
#include <TlHelp32.h>

#include "process.hpp"

void SetOtherThreadsSuspended(bool suspend)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(hSnapshot, &te))
        {
            DWORD currentProcessId = GetCurrentProcessId();
            DWORD currentThreadId = GetCurrentThreadId();
            do
            {
                if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD)
                    && te.th32OwnerProcessID == currentProcessId
                    && te.th32ThreadID != currentThreadId)
                {

                    HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                    if (thread != nullptr)
                    {
                        if (suspend)
                        {
                            SuspendThread(thread);
                        }
                        else
                        {
                            ResumeThread(thread);
                        }
                        CloseHandle(thread);
                    }
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        CloseHandle(hSnapshot);
    }
}
