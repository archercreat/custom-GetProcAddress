#include <Windows.h>
#include "ntdll.h"
#pragma comment(lib, "ntdll.lib")

PPEB GetCurrentPeb()
{
	PPEB peb;
	__asm {
		mov eax, fs:[0x30]
		mov[peb], eax
	}
	return peb;
}

DWORD mGetModuleHandle(LPCSTR name)
{
	int lenModule(0);
	for (; name[lenModule]; ++lenModule);		// strlen
	auto peb = GetCurrentPeb();
	if (!peb)
		return 0;
	auto ldr = peb->Ldr;
	auto inMemOrder = &ldr->InLoadOrderModuleList;
	auto tail = inMemOrder->Blink;
	auto flink = inMemOrder->Flink;
	do
	{
		auto entry = (PLDR_DATA_TABLE_ENTRY)flink;
		for (int i = 0; i < entry->BaseDllName.Length / 2; ++i) {
			if (name[i] == '\0') // end of str
				break;
			else if (name[i] != entry->BaseDllName.Buffer[i])
				break;
			else if (i == lenModule - 1)
				return (DWORD)entry->DllBase;
		}
		flink = flink->Flink;

	} while (flink != tail);
	return 0;
}

int mStrCmp(const char* str1, const char* str2) {
	while (*str1 && *str2) {
		if (*str1 < *str2)
			return -1;
		if (*str1 > *str2)
			return 1;
		++str1; ++str2;
	}
	return *str1 ? -1 : *str2 ? 1 : 0;
}

DWORD mGetProcAddress(LPCSTR module, LPCSTR api)
{ 
	auto base = mGetModuleHandle(module);
	if (!base)
		return 0;
	auto pDOS = (PIMAGE_DOS_HEADER)base;
	if (pDOS->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;
	auto pNT = (PIMAGE_NT_HEADERS)(base + (DWORD)pDOS->e_lfanew);
	if (pNT->Signature != IMAGE_NT_SIGNATURE)
		return 0;
	auto pExport = (PIMAGE_EXPORT_DIRECTORY)(base + pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (!pExport)
		return 0;
	auto names = (PDWORD)(base + pExport->AddressOfNames);
	auto ordinals = (PWORD)(base + pExport->AddressOfNameOrdinals);
	auto functions = (PDWORD)(base + pExport->AddressOfFunctions);
	for (int i = 0; i < pExport->NumberOfFunctions; ++i) {
		auto name = (LPCSTR)(base + names[i]);
		if (!mStrCmp(name, api))
			return base + functions[ordinals[i]];
	}
}
