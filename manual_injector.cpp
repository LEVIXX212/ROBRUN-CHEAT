#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>

struct MANUAL_MAPPING_DATA { BYTE* pLoadLibraryA; BYTE* pGetProcAddress; BYTE* pImageBase; };

#pragma warning(disable: 4244)
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) {
    if (!pData) return;
    BYTE* pBase = pData->pImageBase;
    auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pBase)->e_lfanew)->OptionalHeader;
    auto _LoadLibraryA = reinterpret_cast<decltype(&LoadLibraryA)>(pData->pLoadLibraryA);
    auto _GetProcAddress = reinterpret_cast<decltype(&GetProcAddress)>(pData->pGetProcAddress);
    typedef BOOL(WINAPI* DllMain_t)(HMODULE, DWORD, LPVOID);
    auto _DllMain = reinterpret_cast<DllMain_t>(pOpt->AddressOfEntryPoint + (DWORD_PTR)pBase);
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (pRelocData->VirtualAddress) {
            UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);
            for (UINT i = 0; i < AmountOfEntries; ++i, ++pRelativeInfo) {
                if ((*pRelativeInfo >> 12) == IMAGE_REL_BASED_DIR64) {
                    DWORD_PTR* pPatch = reinterpret_cast<DWORD_PTR*>(pBase + pRelocData->VirtualAddress + (*pRelativeInfo & 0xFFF));
                    *pPatch += reinterpret_cast<DWORD_PTR>(pBase) - pOpt->ImageBase;
                }
            }
            pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
        }
    }
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImportDescr->Name) {
            char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
            HMODULE hDll = _LoadLibraryA(szMod);
            ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
            ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);
            if (!pThunkRef) pThunkRef = pFuncRef;
            for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
                else { auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef)); *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name); }
            }
            ++pImportDescr;
        }
    }
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
        for (; pCallback && *pCallback; ++pCallback) (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
    }
    _DllMain(reinterpret_cast<HMODULE>(pBase), DLL_PROCESS_ATTACH, nullptr);
}
#pragma warning(default: 4244)DWORD GetProcessId(const char* name) {
    DWORD pid = 0; HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) { do { if (!_stricmp(pe.szExeFile, name)) { pid = pe.th32ProcessID; break; } } while (Process32Next(snap, &pe)); }
        CloseHandle(snap);
    }
    return pid;
}

bool ManualMap(HANDLE hProc, const char* dllPath) {
    std::ifstream File(dllPath, std::ios::binary | std::ios::ate);
    if (File.fail()) return false;
    auto FileSize = File.tellg(); if (FileSize < 0x1000) return false;
    BYTE* pSrcData = new BYTE[(UINT_PTR)FileSize];
    File.seekg(0, std::ios::beg); File.read((char*)pSrcData, FileSize); File.close();
    auto* pDosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData);
    auto* pNtHdr = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + pDosHdr->e_lfanew);
    void* pTargetBase = VirtualAllocEx(hProc, nullptr, pNtHdr->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pTargetBase) { delete[] pSrcData; return false; }
    MANUAL_MAPPING_DATA data{ 0 };
    data.pLoadLibraryA = (BYTE*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    data.pGetProcAddress = (BYTE*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");
    data.pImageBase = (BYTE*)pTargetBase;
    void* pData = VirtualAllocEx(hProc, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProc, pData, &data, sizeof(MANUAL_MAPPING_DATA), nullptr);
    WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr);
    auto* pSectionHeader = IMAGE_FIRST_SECTION(pNtHdr);
    for (UINT i = 0; i != pNtHdr->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData) WriteProcessMemory(hProc, (void*)((DWORD_PTR)pTargetBase + pSectionHeader->VirtualAddress), (void*)((DWORD_PTR)pSrcData + pSectionHeader->PointerToRawData), pSectionHeader->SizeOfRawData, nullptr);
    }
    void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr);
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)pShellcode, pData, 0, nullptr);
    if (!hThread) { VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE); VirtualFreeEx(hProc, pData, 0, MEM_RELEASE); VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE); delete[] pSrcData; return false; }
    WaitForSingleObject(hThread, 5000); CloseHandle(hThread);
    VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE); VirtualFreeEx(hProc, pData, 0, MEM_RELEASE);
    DWORD oldProtect; VirtualProtectEx(hProc, pTargetBase, 0x1000, PAGE_READWRITE, &oldProtect);
    BYTE nullBytes[0x1000] = { 0 }; WriteProcessMemory(hProc, pTargetBase, nullBytes, 0x1000, nullptr);
    VirtualProtectEx(hProc, pTargetBase, 0x1000, oldProtect, &oldProtect);
    delete[] pSrcData; return true;
}

int main() {
    std::cout << "--- Manual Map Injector ---\n";
    const char* targetProcess = "ROBRUN.exe"; const char* dllPath = "robrun_hvh.dll";
    DWORD pid = GetProcessId(targetProcess);
    if (!pid) { std::cout << "[-] Process not found. Launch the game first.\n"; system("pause"); return 1; }
    std::cout << "[+] Found PID: " << pid << "\n";
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { std::cout << "[-] OpenProcess failed. Run as Admin or EAC blocks it.\n"; system("pause"); return 1; }
    std::cout << "[*] Injecting via Manual Map...\n";
    if (ManualMap(hProc, dllPath)) std::cout << "[+] SUCCESS! DLL Mapped.\n"; else std::cout << "[-] FAILED.\n";
    CloseHandle(hProc); system("pause"); return 0;
}
