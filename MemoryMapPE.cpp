#include <stdio.h>
#include <windows.h>
#include "WoWMIPS.h"

DWORD MemoryMapPE_LoadFileIntoMemory(char *pPath, BYTE **pFileData, DWORD *pdwFileSize)
{
	HANDLE hFile = NULL;
	DWORD dwFileSize = 0;
	BYTE *pFileDataBuffer = NULL;
	DWORD dwBytesRead = 0;

	// open file
	hFile = CreateFileA(pPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		return 1;
	}

	// calculate file size
	dwFileSize = GetFileSize(hFile, NULL);

	// allocate buffer
	pFileDataBuffer = (BYTE*)malloc(dwFileSize);
	if(pFileDataBuffer == NULL)
	{
		CloseHandle(hFile);
		return 1;
	}

	// read file contents
	if(ReadFile(hFile, pFileDataBuffer, dwFileSize, &dwBytesRead, NULL) == 0)
	{
		free(pFileDataBuffer);
		CloseHandle(hFile);
		return 1;
	}

	// verify byte count
	if(dwBytesRead != dwFileSize)
	{
		free(pFileDataBuffer);
		CloseHandle(hFile);
		return 1;
	}

	// close file handle
	CloseHandle(hFile);

	// store values
	*pFileData = pFileDataBuffer;
	*pdwFileSize = dwFileSize;

	return 0;
}

DWORD MemoryMapPE_FixRelocs(BYTE *pImageBase, IMAGE_NT_HEADERS32 *pImageNtHeader)
{
	DWORD dwBaseDelta = 0;
	IMAGE_BASE_RELOCATION *pImageBaseReloc = NULL;
	BYTE *pCurrRelocArea = NULL;
	DWORD dwCurrRelocCount = 0;
	WORD wCurrRelocEntry = 0;
	WORD wRelocOffset = 0;
	WORD wRelocType = 0;
	DWORD dwCurrRelocBlockOffset = 0;
	BYTE *pCurrRelocEntryPtr = NULL;
	BYTE *pCurrRelocTargetPtr = NULL;
	DWORD dwExistingValue32 = 0;
	WORD wExistingValue16 = 0;
	WORD *pwNextValue = NULL;

	// ensure this module supports dynamic base addresses
	if((pImageNtHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0)
	{
		// relocs stripped - error
		return 1;
	}

	// calculate base address delta
	dwBaseDelta = (DWORD)pImageBase - (DWORD)pImageNtHeader->OptionalHeader.ImageBase;

	if(pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size != 0)
	{
		for(;;)
		{
			// get image base reloc data
			pImageBaseReloc = (IMAGE_BASE_RELOCATION*)(pImageBase + pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + dwCurrRelocBlockOffset);
			if(pImageBaseReloc->VirtualAddress == 0)
			{
				// finished
				break;
			}

			// get current reloc block details
			pCurrRelocArea = pImageBase + pImageBaseReloc->VirtualAddress;
			dwCurrRelocCount = (pImageBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			// there is no information about MIPS relocs online - i reverse-engineered the ntdll!LdrProcessRelocationBlock function and replicated the same behaviour
			for(DWORD i = 0; i < dwCurrRelocCount; i++)
			{
				// get current reloc entry
				pCurrRelocEntryPtr = (BYTE*)((BYTE*)pImageBaseReloc + sizeof(IMAGE_BASE_RELOCATION) + (i * sizeof(WORD)));
				wCurrRelocEntry = *(WORD*)pCurrRelocEntryPtr;
				wRelocOffset = wCurrRelocEntry & 0xFFF;
				wRelocType = wCurrRelocEntry >> 12;
				pCurrRelocTargetPtr = (BYTE*)((BYTE*)pCurrRelocArea + wRelocOffset);
				dwExistingValue32 = *(DWORD*)pCurrRelocTargetPtr;
				wExistingValue16 = *(WORD*)pCurrRelocTargetPtr;

				// process current entry
				if(wRelocType == IMAGE_REL_BASED_ABSOLUTE)
				{
					continue;
				}
				else if(wRelocType == IMAGE_REL_BASED_HIGH)
				{
					*(WORD*)pCurrRelocTargetPtr = (WORD)((((DWORD)wExistingValue16 << 16) + dwBaseDelta) >> 16);
				}
				else if(wRelocType == IMAGE_REL_BASED_LOW)
				{
					*(WORD*)pCurrRelocTargetPtr = wExistingValue16 + (WORD)dwBaseDelta;
				}
				else if(wRelocType == IMAGE_REL_BASED_HIGHLOW)
				{
					*(DWORD*)pCurrRelocTargetPtr = dwExistingValue32 + dwBaseDelta;
				}
				else if(wRelocType == IMAGE_REL_BASED_HIGHADJ)
				{
					pwNextValue = (WORD*)((BYTE*)pCurrRelocEntryPtr + sizeof(WORD));
					i++;
					*(WORD*)pCurrRelocTargetPtr = (WORD)((((DWORD)wExistingValue16 << 16) + ((DWORD)((short)*pwNextValue)) + dwBaseDelta + 0x8000) >> 16);
				}
				else if(wRelocType == IMAGE_REL_BASED_MIPS_JMPADDR)
				{
					*(DWORD*)pCurrRelocTargetPtr = (dwExistingValue32 & 0xFC000000) + (((((dwExistingValue32 & 0x3FFFFFF) << 2) + dwBaseDelta) >> 2) & 0x3FFFFFF);
				}
				else
				{
					// invalid reloc type
					return 1;
				}
			}

			// update reloc block offset
			dwCurrRelocBlockOffset += pImageBaseReloc->SizeOfBlock;
		}
	}

	return 0;
}

DWORD TranslateImportedAddress(DWORD dwTargetFunction, char *pModuleName, char *pFunctionName, DWORD *pdwTranslatedFunctionAddress)
{
	DWORD dwDataOnlyImport = 0;
	DWORD dwTranslatedFunctionAddress = 0;
	BYTE *pCode = NULL;
	char szNativeFunction[1024];

	memset(szNativeFunction, 0, sizeof(szNativeFunction));
	_snprintf(szNativeFunction, sizeof(szNativeFunction) - 1, "%s!%s", pModuleName, pFunctionName);

	// check if this is a data-only import (non-executable)
	dwDataOnlyImport = 0;
	if(dwTargetFunction != 0)
	{
		// check if this export resides within an executable region
		if(ValidatePtrExec((BYTE*)dwTargetFunction, 1) != 0)
		{
			// not executable
			dwDataOnlyImport = 1;
		}
 	}

	if(dwDataOnlyImport != 0)
	{
		// set data-only import address directly
		dwTranslatedFunctionAddress = (DWORD)dwTargetFunction;
	}
	else
	{
		// allocate a virtual instruction - store import name
		pCode = (BYTE*)malloc(sizeof(DWORD) + sizeof(DWORD) + sizeof(szNativeFunction));
		if(pCode == NULL)
		{
			return 1;
		}

		// write NATIVECALL custom instruction
		*(DWORD*)pCode = (DWORD)(NATIVECALL_OPCODE << 26);
		*(DWORD*)((BYTE*)pCode + sizeof(DWORD)) = dwTargetFunction;
		memcpy(((BYTE*)pCode + sizeof(DWORD) + sizeof(DWORD)), (void*)szNativeFunction, sizeof(szNativeFunction));

		// set import address
		dwTranslatedFunctionAddress = (DWORD)pCode;
	}

	*pdwTranslatedFunctionAddress = dwTranslatedFunctionAddress;

	return 0;
}

FARPROC WINAPI Hook_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
	DWORD dwAddress = 0;
	DWORD dwTranslatedFunctionAddress = 0;
	char szCurrFunctionName[128];
	char szCurrModulePath[512];
	char *pCurrModuleName = NULL;

	dwAddress = (DWORD)GetProcAddress(hModule, lpProcName);
	if(dwAddress == 0)
	{
		return NULL;
	}

	// check if this is a named/ordinal entry
	if((DWORD)lpProcName <= 0xFFFF)
	{
		_snprintf(szCurrFunctionName, sizeof(szCurrFunctionName) - 1, "#%u", (DWORD)lpProcName);
	}
	else
	{
		_snprintf(szCurrFunctionName, sizeof(szCurrFunctionName) - 1, "%s", lpProcName);
	}

	// extract file name from full module path
	memset(szCurrModulePath, 0, sizeof(szCurrModulePath));
	GetModuleFileNameA(hModule, szCurrModulePath, sizeof(szCurrModulePath) - 1);
	pCurrModuleName = strrchr(szCurrModulePath, '\\');
	if(pCurrModuleName == NULL)
	{
		return NULL;
	}
	pCurrModuleName++;

	// translate import address - generate NATIVECALL instruction if necessary
	if(TranslateImportedAddress(dwAddress, pCurrModuleName, szCurrFunctionName, &dwTranslatedFunctionAddress) != 0)
	{
		return NULL;
	}

	return (FARPROC)dwTranslatedFunctionAddress;
}

DWORD MemoryMapPE_FixImports(BYTE *pImageBase, IMAGE_NT_HEADERS32 *pImageNtHeader)
{
	IMAGE_IMPORT_DESCRIPTOR *pImageImportDescriptor = NULL;
	DWORD dwCurrImportBlockOffset = 0;
	char *pCurrModuleName = NULL;
	HMODULE hCurrModule = NULL;
	IMAGE_THUNK_DATA *pBaseFirstThunkData = NULL;
	IMAGE_THUNK_DATA *pBaseOriginalFirstThunkData = NULL;
	IMAGE_THUNK_DATA *pCurrThunkData = NULL;
	IMAGE_THUNK_DATA *pCurrOriginalThunkData = NULL;
	DWORD dwCurrThunkOffset = 0;
	IMAGE_IMPORT_BY_NAME *pImageImportByName = NULL;
	BYTE *pImportedFunctionAddr = NULL;
	DWORD dwOrdinal = 0;
	HMODULE hModule = NULL;
	DWORD dwTargetFunction = 0;
	DWORD dwTranslatedFunctionAddress = 0;
	char szCurrFunctionName[128];

	if(pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)
	{
		// process import table
		for(;;)
		{
			pImageImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)pImageBase + pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + dwCurrImportBlockOffset);
			if(pImageImportDescriptor->Name == 0)
			{
				// finished
				break;
			}

			// load current module
			pCurrModuleName = (char*)((BYTE*)pImageBase + pImageImportDescriptor->Name);

			hModule = LoadLibraryA(pCurrModuleName);
			if(hModule == NULL)
			{
				printf("Warning: Library '%s' not found\n", pCurrModuleName);
			}

			pBaseFirstThunkData = (IMAGE_THUNK_DATA*)((BYTE*)pImageBase + pImageImportDescriptor->FirstThunk);
			if(pImageImportDescriptor->OriginalFirstThunk != 0)
			{
				pBaseOriginalFirstThunkData = (IMAGE_THUNK_DATA*)((BYTE*)pImageBase + pImageImportDescriptor->OriginalFirstThunk);
			}
			else
			{
				// some linkers don't use OriginalFirstThunk - use FirstThunk instead
				pBaseOriginalFirstThunkData = pBaseFirstThunkData;
			}

			// process module imports
			dwCurrThunkOffset = 0;
			for(;;)
			{
				// get current thunk ptrs
				pCurrThunkData = (IMAGE_THUNK_DATA*)((BYTE*)pBaseFirstThunkData + dwCurrThunkOffset);
				pCurrOriginalThunkData = (IMAGE_THUNK_DATA*)((BYTE*)pBaseOriginalFirstThunkData + dwCurrThunkOffset);

				if(pCurrOriginalThunkData->u1.AddressOfData == 0)
				{
					// finished
					break;
				}

				// reset target function address
				dwTargetFunction = 0;

				// check import type
				memset(szCurrFunctionName, 0, sizeof(szCurrFunctionName));
				if(pCurrOriginalThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					// resolve import by ordinal
					dwOrdinal = pCurrOriginalThunkData->u1.Ordinal & 0xFFFF;
					_snprintf(szCurrFunctionName, sizeof(szCurrFunctionName) - 1, "#%u", dwOrdinal);

					if(hModule != NULL)
					{
						dwTargetFunction = (DWORD)GetProcAddress(hModule, (char*)dwOrdinal);
					}
				}
				else
				{
					// get imported function name
					pImageImportByName = (IMAGE_IMPORT_BY_NAME*)((BYTE*)pImageBase + (DWORD)pCurrOriginalThunkData->u1.AddressOfData);
					_snprintf(szCurrFunctionName, sizeof(szCurrFunctionName) - 1, "%s", pImageImportByName->Name);

					if(hModule != NULL)
					{
						dwTargetFunction = (DWORD)GetProcAddress(hModule, (char*)pImageImportByName->Name);
					}
				}

				if(strcmp(szCurrFunctionName, "GetProcAddress") == 0)
				{
					// hook GetProcAddress
					dwTargetFunction = (DWORD)Hook_GetProcAddress;
				}

				// translate import address - generate NATIVECALL instruction if necessary
				if(TranslateImportedAddress(dwTargetFunction, pCurrModuleName, szCurrFunctionName, &dwTranslatedFunctionAddress) != 0)
				{
					return 1;
				}
				pCurrThunkData->u1.Function = (DWORD*)dwTranslatedFunctionAddress;

				// update thunk offset
				dwCurrThunkOffset += sizeof(IMAGE_THUNK_DATA);
			}

			// update import block offset
			dwCurrImportBlockOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		}
	}

	return 0;
}

DWORD MemoryMapPE(char *pFilePath, BYTE **ppImageBase, IMAGE_NT_HEADERS32 **ppImageNtHeader)
{
	IMAGE_DOS_HEADER *pImageDosHeader = NULL;
	IMAGE_NT_HEADERS32 *pImageNtHeader = NULL;
	BYTE *pImageBase = NULL;
	IMAGE_SECTION_HEADER *pCurrSectionHeader = NULL;
	BYTE *pFileData = NULL;
	DWORD dwFileSize = 0;

	if(MemoryMapPE_LoadFileIntoMemory(pFilePath, &pFileData, &dwFileSize) != 0)
	{
		return 1;
	}

	// get dos header
	pImageDosHeader = (IMAGE_DOS_HEADER*)pFileData;
	if(pImageDosHeader->e_magic != 0x5A4D)
	{
		free(pFileData);
		return 1;
	}

	// get nt header
	pImageNtHeader = (IMAGE_NT_HEADERS32*)(pFileData + pImageDosHeader->e_lfanew);
	if(pImageNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		free(pFileData);
		return 1;
	}

	// validate exe type
	if(pImageNtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_R4000)
	{
		free(pFileData);
		return 1;
	}

	// attempt to map the image at the desired base address
	pImageBase = (BYTE*)VirtualAlloc((void*)pImageNtHeader->OptionalHeader.ImageBase, pImageNtHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if(pImageBase == NULL)
	{
		// failed to allocate at desired base, try elsewhere
		pImageBase = (BYTE*)VirtualAlloc(NULL, pImageNtHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if(pImageBase == NULL)
		{
			free(pFileData);
			return 1;
		}
	}

	// copy PE headers
	memcpy((void*)pImageBase, pFileData, pImageNtHeader->OptionalHeader.SizeOfHeaders);

	// copy section data
	for(DWORD i = 0; i < pImageNtHeader->FileHeader.NumberOfSections; i++)
	{
		// get current section header
		pCurrSectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)&pImageNtHeader->OptionalHeader + pImageNtHeader->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		if(pCurrSectionHeader->SizeOfRawData != 0)
		{
			memcpy((void*)((BYTE*)pImageBase + pCurrSectionHeader->VirtualAddress), ((BYTE*)pFileData + pCurrSectionHeader->PointerToRawData), pCurrSectionHeader->SizeOfRawData);
		}
	}

	// update nt header pointer - use memory image data instead, file data will be free'd soon
	pImageNtHeader = (IMAGE_NT_HEADERS32*)(pImageBase + pImageDosHeader->e_lfanew);

	// free original file data
	free(pFileData);

	// check if relocs need to be processed
	if(pImageBase != (BYTE*)pImageNtHeader->OptionalHeader.ImageBase)
	{
		// fix relocs
		if(MemoryMapPE_FixRelocs(pImageBase, pImageNtHeader) != 0)
		{
			VirtualFree((void*)pImageBase, 0, MEM_RELEASE);
			return 1;
		}
	}

	// fix imports
	if(MemoryMapPE_FixImports(pImageBase, pImageNtHeader) != 0)
	{
		VirtualFree((void*)pImageBase, 0, MEM_RELEASE);
		return 1;
	}

	// store image info
	*ppImageBase = pImageBase;
	*ppImageNtHeader = pImageNtHeader;

	return 0;
}
