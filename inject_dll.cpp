#include <iostream>
#include <Windows.h>

int main(int argc, char* argv[])
{
    const char* DLL_Path = "C:\\test.dll";

    HANDLE Process_Handle = OpenProcess(PROCESS_ALL_ACCESS, 0, DWORD(atoi(argv[1])));
    PVOID Alloc = VirtualAllocEx(Process_Handle, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (Alloc)
    {
        WriteProcessMemory(Process_Handle, Alloc, DLL_Path, strlen(DLL_Path) + 1, NULL);
    }
    HANDLE Remote_Thread = CreateRemoteThread(Process_Handle, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, Alloc, 0, NULL);
    CloseHandle(Remote_Thread);
    CloseHandle(Process_Handle);

    return 0;
}
