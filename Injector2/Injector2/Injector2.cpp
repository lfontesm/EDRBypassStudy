// Injector2.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#undef UNICODE

#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

HANDLE OpenProcessByName(char *procName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);


    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (Process32First(snapshot, &entry)) {
        while (Process32Next(snapshot, &entry)) {
            if (strncmp(entry.szExeFile, procName, strlen(procName)) == 0) {
                printf("Found %s\n", procName);
                HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, entry.th32ProcessID);
                if (!hProc) {
                    printf("Failed to open remote process with the given permissions\n");
                    exit(1);
                }
                return hProc;
            }
        }
    }
    return NULL;
}

int main(){
    char* procname = (char*)"notepad.exe";

    HANDLE targetProc = OpenProcessByName(procname);
    printf("Handle: %p\n", targetProc);

    HMODULE hKern32 = GetModuleHandle("kernel32.dll");

    if (!hKern32) {
        printf("Failed to load kernel32.dll\n");
        exit(1);
    }

    FARPROC loadLibAddr = GetProcAddress(hKern32, "LoadLibraryA");

    if (!loadLibAddr) {
        printf("Failed during the LoadLibraryA lookup\n");
        exit(1);
    }

    char* dllName = (char*)"C:\\Users\\user\\Desktop\\EDRBypassStudies\\mydll\\x64\\Release\\mydll.dll";

    LPVOID allocMemAddress = VirtualAllocEx(targetProc, NULL, strlen(dllName) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!allocMemAddress) {
        printf("Failed to allocate remote memory\n");
        exit(1);
    }

    WriteProcessMemory(targetProc, allocMemAddress, dllName, strlen(dllName) + 1, NULL);

    CreateRemoteThread(targetProc, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, allocMemAddress, 0, NULL);

    CloseHandle(targetProc);

    return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
