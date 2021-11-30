#include <Windows.h>
#include <stdio.h>
#include <intrin.h>

#include "hook.h"
#include "hde64.h"

// Use _InterlockedCompareExchange64 insted of inline ASM (depends on compiler)
#define NO_INLINE_ASM
#undef UNICODE

TdefOldMessageBoxA OldMessageBoxA;
TdefOldMessageBoxW OldMessageBoxW;

LPVOID originalMemArea;

HOOK_ARRAY HookArray[] =
{
	{"user32.dll", "MessageBoxA", (LPVOID)&NewMessageBoxA, &OldMessageBoxA, 0},
	//{"user32.dll", "MessageBoxW", (LPVOID)&NewMessageBoxA, &OldMessageBoxW, 0},
};

//We need to copy 5 bytes, but we can only do 2, 4, 8 atomically
//Pad buffer to 8 bytes then use lock cmpxchg8b instruction
void SafeMemcpyPadded(LPVOID destination, LPVOID source, DWORD size) {
	BYTE SourceBuffer[8];

	if (size > 8)
		return;

	//Pad the source buffer with bytes from destination
	memcpy(SourceBuffer, destination, 8);
	memcpy(SourceBuffer, source, size);

#ifndef NO_INLINE_ASM
	__asm
	{
		lea esi, SourceBuffer;
		mov edi, destination;

		mov eax, [edi];
		mov edx, [edi + 4];
		mov ebx, [esi];
		mov ecx, [esi + 4];

		lock cmpxchg8b[edi];
	}
#else
	_InterlockedCompareExchange64((LONGLONG*)destination, *(LONGLONG*)SourceBuffer, *(LONGLONG*)destination);
#endif
}

int WINAPI NewMessageBoxA(HWND hWnd, LPCSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	printf("MessageBoxA called!\ntitle: %s\ntext: %s\n\n", lpCaption, lpText);
	return OldMessageBoxA(hWnd, lpText, lpCaption, uType);
}

BOOL HookFunction(CHAR* dll, CHAR* name, LPVOID proxy, LPVOID original, PDWORD length) {
	LPVOID funcAddr;
	DWORD trampolineLength = 0, originalProtection;
	hde64s disasm;
	BYTE jump[9]{ 0xe9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

	funcAddr = GetProcAddress(GetModuleHandleA(dll), name);
	if (!funcAddr) {
		printf("Failed to hook %s\n", name);
		return false;
	}

	// Disassemble length of each instruction, until we have 9 or more bytes worth
	while (trampolineLength < 9) {
		LPVOID instPointer = (LPVOID)((DWORD)funcAddr + trampolineLength);
		trampolineLength += hde64_disasm(instPointer, &disasm);
	}

	// Build the trampoline buffer
	memcpy(original, funcAddr, trampolineLength);
	*(DWORD*)(jump + 1) = ((DWORD)funcAddr + trampolineLength) - ((DWORD)original + trampolineLength + 9);
	memcpy((LPVOID)((DWORD)original + trampolineLength), jump, 9);

	// Make sure the function is writable
	if (!VirtualProtect(funcAddr, trampolineLength, PAGE_EXECUTE_READWRITE, &originalProtection)) {
		printf("Failed to change memory protection for %s\n", name);
		return false;
	}

	// Build and atomically write the hook
	*(DWORD*)(jump + 1) = (DWORD)proxy - (DWORD)funcAddr - 9;
	SafeMemcpyPadded(funcAddr, jump, 9);

	// Restore the original page protection
	VirtualProtect(funcAddr, trampolineLength, originalProtection, &originalProtection);

	// Clear CPU instruction cache
	FlushInstructionCache(GetCurrentProcess(), funcAddr, trampolineLength);

	*length = trampolineLength;

	return true;
}

BOOL UnhookFunction(CHAR* dll, CHAR* name, LPVOID original, DWORD length) {
	LPVOID funcAddr;
	DWORD originalProtect;

	funcAddr = GetProcAddress(GetModuleHandleA(dll), name);
	if (!funcAddr) {
		printf("Unexpected error while unhooking %s\n", name);
		return false;
	}

	if (!VirtualProtect(funcAddr, length, PAGE_EXECUTE_READWRITE, &originalProtect)) {
		printf("Failed to change memory protection of %s\n");
		return false;
	}

	SafeMemcpyPadded(funcAddr, original, length);

	VirtualProtect(funcAddr, length, originalProtect, &originalProtect);

	FlushInstructionCache(GetCurrentProcess(), funcAddr, length);

	return true;
}

void HookAll() {
	int NumEntries = sizeof(HookArray) / sizeof(HOOK_ARRAY);

	// Needs 25 bytes for each hooked function to hold original byte + return jump
	originalMemArea = VirtualAlloc(NULL, 25 * NumEntries, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!originalMemArea) {
		printf("Failed to allocated mem for storing original functions");
		exit(1);
	}

	for (int i = 0; i < NumEntries; i++) {
		// Split allocated memory into a block of 29 bytes for each hooked function
		*(LPVOID*)HookArray[i].original = (LPVOID)((DWORD)originalMemArea + (i * 29));
		HookFunction((char *)HookArray[i].dll, (char *)HookArray[i].name, *(LPVOID*)HookArray[i].original, &HookArray[i].length);
	}
}



int main() {
	HookAll();
	
	MessageBoxA(NULL, "Testing", "Hook", MB_OK);
}