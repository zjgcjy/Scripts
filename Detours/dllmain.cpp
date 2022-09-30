#include <iostream>
#include <fstream>
#include <Windows.h>
#include "detours.h"

static auto p1 = CreateFileA;
static auto p2 = DeleteFileA;
std::ofstream outF("D://log.txt", std::ios::out);

BOOL
WINAPI
MyDeleteFileA(
    _In_ LPCSTR lpFileName
)
{
    outF << "[DeleteFile Start]" << std::endl;
    outF << "filename: " << lpFileName << std::endl;
    //BOOL f = p2(lpFileName);
    outF << "[DeleteFile End]" << std::endl;
    return TRUE;
}


HANDLE
WINAPI
MyCreateFileA(
    _In_ LPCSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
)
{
    
    outF << "[CreateFile Start]" << std::endl;
    
    if (dwDesiredAccess & DELETE)
    {
        outF << "DELETE FILE" << std::endl;
        HANDLE a = p1(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
        outF << "[CreateFile End]" << std::endl;
        return a;

    }
    outF << "filename: " << lpFileName << " access: " << std::hex <<dwDesiredAccess << std::endl;
    HANDLE a = p1(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    outF << "[CreateFile End]" << std::endl;
    return a;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    if (DetourIsHelperProcess()) 
    {
        return TRUE;
    }

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)p1, MyCreateFileA);
        DetourAttach(&(PVOID&)p2, MyDeleteFileA);
        DetourTransactionCommit();
        break;

    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)p1, MyCreateFileA);
        DetourAttach(&(PVOID&)p2, MyDeleteFileA);
        DetourTransactionCommit();
        break;
    }
    return TRUE;
}