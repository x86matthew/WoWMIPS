#include <stdio.h>
#include <windows.h>
#include "WoWMIPS.h"

PEB *GetPeb()
{
	PEB *pPEB = NULL;

	_asm
	{
		push eax
		mov eax, fs:[0x30]
		mov pPEB, eax
		pop eax
	}

	return pPEB;
}

LDR_DATA_TABLE_ENTRY *GetPebLdrDataTableEntry(BYTE *pModuleBase)
{
	PEB *pPEB = NULL;
	LDR_DATA_TABLE_ENTRY *pCurrEntry = NULL;
	LIST_ENTRY *pListHead = NULL;
	LIST_ENTRY *pCurrListEntry = NULL;
	DWORD dwInMemoryOrderLinksOffset = 0;

	// get PEB ptr
	pPEB = GetPeb();

	// get InMemoryOrderLinks offset in structure
	dwInMemoryOrderLinksOffset = (DWORD)((BYTE*)&pCurrEntry->InMemoryOrderLinks - (BYTE*)pCurrEntry);

	// loop over PEB_LDR module entries
	pListHead = &pPEB->Ldr->InMemoryOrderModuleList;
	pCurrListEntry = pListHead->Flink;
	for(;;)
	{
		// check if this is the final entry
		if(pCurrListEntry == pListHead)
		{
			break;
		}

		// get ptr to current module entry
		pCurrEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pCurrListEntry - dwInMemoryOrderLinksOffset);

		if(pCurrEntry->DllBase == (void*)pModuleBase)
		{
			return pCurrEntry;
		}

		// get next module entry in list
		pCurrListEntry = pCurrListEntry->Flink;
	}

	return NULL;
}

DWORD HookFunction(BYTE *pFunctionAddr, BYTE *pHookFunctionAddr)
{
	BYTE bJumpCode[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
	DWORD dwOrigProtect = 0;

	// set relative 32-bit address
	*(DWORD*)&bJumpCode[1] = (DWORD)pHookFunctionAddr - ((DWORD)pFunctionAddr + 5);

	// adjust protection
	if(VirtualProtect(pFunctionAddr, sizeof(bJumpCode), PAGE_EXECUTE_READWRITE, &dwOrigProtect) == 0)
	{
		return 1;
	}

	// copy hook
	memcpy((void*)pFunctionAddr, (void*)bJumpCode, sizeof(bJumpCode));

	// restore protection
	if(VirtualProtect(pFunctionAddr, sizeof(bJumpCode), dwOrigProtect, &dwOrigProtect) == 0)
	{
		return 1;
	}

	return 0;
}

DWORD CheckAddressInModule(const char *pModuleName, BYTE *pAddress)
{
	HMODULE hModule = NULL;
	MEMORY_BASIC_INFORMATION MemoryBasicInformation;

	hModule = GetModuleHandleA(pModuleName);
	if(hModule == NULL)
	{
		return 1;
	}

	memset((void*)&MemoryBasicInformation, 0, sizeof(MemoryBasicInformation));
	if(VirtualQuery((void*)pAddress, &MemoryBasicInformation, sizeof(MemoryBasicInformation)) == 0)
	{
		return 1;
	}
	
	if(MemoryBasicInformation.State != MEM_COMMIT)
	{
		return 1;
	}
	
	if(MemoryBasicInformation.AllocationBase != (void*)hModule)
	{
		return 1;
	}

	return 0;
}

DWORD ValidatePtrProtection(BYTE *pMemory, DWORD dwLength, DWORD dwValidFlags)
{
	BYTE *pCurrPage = NULL;
	MEMORY_BASIC_INFORMATION MemoryBasicInformation;

	// round down to current page base
	pCurrPage = (BYTE*)((DWORD)pMemory & 0xFFFFF000);

	// check all pages within range
	for(;;)
	{
		if(pCurrPage >= (BYTE*)(pMemory + dwLength))
		{
			break;
		}

		memset((void*)&MemoryBasicInformation, 0, sizeof(MemoryBasicInformation));
		if(VirtualQuery((void*)pMemory, &MemoryBasicInformation, sizeof(MemoryBasicInformation)) == 0)
		{
			return 1;
		}

		if(MemoryBasicInformation.State != MEM_COMMIT)
		{
			return 1;
		}

		if((MemoryBasicInformation.Protect & dwValidFlags) == 0)
		{
			return 1;
		}

		// move to next page
		pCurrPage += 0x1000;
	}

	return 0;
}

DWORD ValidatePtrRead(BYTE *pMemory, DWORD dwLength)
{
	if(ValidatePtrProtection(pMemory, dwLength, PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY) != 0)
	{
		return 1;
	}

	return 0;
}

DWORD ValidatePtrWrite(BYTE *pMemory, DWORD dwLength)
{
	if(ValidatePtrProtection(pMemory, dwLength, PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_READWRITE | PAGE_WRITECOPY) != 0)
	{
		return 1;
	}

	return 0;
}

DWORD ValidatePtrExec(BYTE *pMemory, DWORD dwLength)
{
	if(ValidatePtrProtection(pMemory, dwLength, PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) != 0)
	{
		return 1;
	}

	return 0;
}
