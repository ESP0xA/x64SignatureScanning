/********************************************************************************
*                                                                               *
* Signature scanning for specific address                                       *
*                                                                               *
* Copyright (c) ESP. All rights reserved.                                       *
*                                                                               *
********************************************************************************/


#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <vector>
HMODULE myhModule;
typedef uint64_t QWORD;

// 释放线程
DWORD __stdcall EjectThread(LPVOID lpParameter) {
    Sleep(100);
    FreeLibraryAndExitThread(myhModule, 0);
}

// 根据签名扫描内存
QWORD GetAddreassFromSignature(std::vector<int> signature, QWORD startaddress = 0, QWORD endaddress = 0) {
    SYSTEM_INFO si; // SYSTEM_INFO structure (sysinfoapi.h)
    GetNativeSystemInfo(&si); // Retrieves information about the current system.
    // 未指定扫描范围
    if (startaddress == 0) {
        startaddress = (QWORD)(si.lpMinimumApplicationAddress);
    }
    if (endaddress == 0) {
        endaddress = (QWORD)(si.lpMaximumApplicationAddress);
    }

    MEMORY_BASIC_INFORMATION mbi{ 0 };
    QWORD protectflags = (PAGE_GUARD | PAGE_NOCACHE | PAGE_NOACCESS);

    for (QWORD i = startaddress; i < endaddress - signature.size(); i++) {
        //std::cout << "scanning: " << std::hex << i << std::endl;
        if (VirtualQuery((LPCVOID)i, &mbi, sizeof(mbi))) {  // if not faild
            if (mbi.Protect & protectflags || !(mbi.State & MEM_COMMIT)) {
                std::cout << "Bad Region! Region Base Address: " << (QWORD)mbi.BaseAddress << " | Region end address: " << std::hex << ((QWORD)mbi.BaseAddress + mbi.RegionSize) << std::endl;
                i += mbi.RegionSize;
                continue;
            }
        }
        std::cout << "Good Region! Region Base Address: " << (QWORD)mbi.BaseAddress << " | Region end address: " << std::hex << ((QWORD)mbi.BaseAddress + mbi.RegionSize) << std::endl;
        for (QWORD k = (QWORD)mbi.BaseAddress; k < (QWORD)mbi.BaseAddress + mbi.RegionSize - signature.size(); k++) {     // loop in region baseaddress
            for (QWORD j = 0; j < signature.size(); j++) {
                if (signature.at(j) != -1 && signature.at(j) != *(BYTE*)(k + j))
                    break;
                //if (signature.at(j) == *(BYTE*)(i + j) && j > 0)
                //    std::cout << std::hex << int(signature.at(j)) << std::hex << int(*(BYTE*)(i + j)) << j << std::endl;
                if (j + 1 == signature.size())
                    return k;
            }
        }
        i = (QWORD)mbi.BaseAddress + mbi.RegionSize;
    }
}


// MENU
QWORD WINAPI Menu() {
    AllocConsole(); 
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    std::cout << "Press end to exit | Press home for scanning" << std::endl;
    while (1) {
        Sleep(100);
        if (GetAsyncKeyState(VK_END))
            break;
        if (GetAsyncKeyState(VK_HOME)) {
            // test signature with gta5 local player address
            std::vector<int> sig = { 0x68, 0xEA, 0xDD, 0x7D, 0xF6, 0x7F, 0x00 };

            QWORD Entry = GetAddreassFromSignature(sig);
            std::cout << "Result: " << std::hex << Entry << std::endl;
            /*  // specific a scanning range
            DWORD Entry = GetAddreassFromSignature(sig, 0x4A000000, 0x5000000);
            if (Entry == NULL)
                Entry = GetAddreassFromSignature(sig, 0x1F000000, 0x4A000000);
            if (Entry == NULL)
                Entry = GetAddreassFromSignature(sig);
            */
        }
    }
    fclose(fp);
    FreeConsole();
    CreateThread(0, 0, EjectThread, 0, 0, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        myhModule = hModule;
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Menu, NULL, 0, NULL);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

