#include <stdio.h>
#include <windows.h>
#include "WoWMIPS.h"

CpuThreadDataStruct Global_CpuThreadList[MAX_CPU_THREAD_COUNT];
CRITICAL_SECTION Global_CpuThreadListCriticalSection;

CpuThreadDataStruct *CPU_GetThreadData()
{
	return (CpuThreadDataStruct*)TlsGetValue(dwGlobal_CpuThreadDataTlsIndex);
}

DWORD CPU_LockThreadList()
{
	EnterCriticalSection(&Global_CpuThreadListCriticalSection);

	return 0;
}

DWORD CPU_UnlockThreadList()
{
	LeaveCriticalSection(&Global_CpuThreadListCriticalSection);

	return 0;
}

CpuThreadDataStruct *CPU_AssignNewThread()
{
	CpuThreadDataStruct *pCpuThreadData = NULL;
	HANDLE hCurrentThread = NULL;

	// check for exited threads
	for(DWORD i = 0; i < MAX_CPU_THREAD_COUNT; i++)
	{
		if(Global_CpuThreadList[i].dwInUse != 0)
		{
			if(WaitForSingleObject(Global_CpuThreadList[i].hThread, 0) == WAIT_OBJECT_0)
			{
				// thread exited
				CloseHandle(Global_CpuThreadList[i].hThread);
				Global_CpuThreadList[i].dwInUse = 0;
			}
		}
	}

	// find a free slot
	for(i = 0; i < MAX_CPU_THREAD_COUNT; i++)
	{
		if(Global_CpuThreadList[i].dwInUse == 0)
		{
			pCpuThreadData = &Global_CpuThreadList[i];
			break;
		}
	}

	if(pCpuThreadData == NULL)
	{
		return NULL;
	}

	if(DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &hCurrentThread, SYNCHRONIZE, 0, 0) == 0)
	{
		return NULL;
	}

	memset((void*)pCpuThreadData, 0, sizeof(CpuThreadDataStruct));
	pCpuThreadData->dwInUse = 1;
	pCpuThreadData->hThread = hCurrentThread;

	// store ptr in TLS
	TlsSetValue(dwGlobal_CpuThreadDataTlsIndex, (void*)pCpuThreadData);

	return pCpuThreadData;
}

DWORD CPU_InitialiseThread()
{
	DWORD dwStackSize = 0;
	BYTE *pStackData = NULL;
	CpuThreadDataStruct *pCpuThreadData = NULL;

	// allocate stack
	dwStackSize = pGlobal_ImageNtHeader->OptionalHeader.SizeOfStackReserve;
	if(pGlobal_ImageNtHeader->OptionalHeader.SizeOfStackCommit > dwStackSize)
	{
		dwStackSize = pGlobal_ImageNtHeader->OptionalHeader.SizeOfStackCommit;
	}
	pStackData = (BYTE*)malloc(dwStackSize);
	if(pStackData == NULL)
	{
		return 1;
	}

	CPU_LockThreadList();

	// store thread-local info
	pCpuThreadData = CPU_AssignNewThread();
	if(pCpuThreadData == NULL)
	{
		CPU_UnlockThreadList();
		free(pStackData);
		return 1;
	}

	pCpuThreadData->pWatchWritePtr = NULL;
	pCpuThreadData->pStackData = pStackData;
	pCpuThreadData->dwStackSize = dwStackSize;

	// initialise emulated PEB structure
	memset((void*)&pCpuThreadData->TEB, 0, sizeof(pCpuThreadData->TEB));

	// TEB.StackBase
	*(DWORD*)((DWORD)&pCpuThreadData->TEB + 4) = (DWORD)pStackData + dwStackSize;
	// TEB.StackLimit
	*(DWORD*)((DWORD)&pCpuThreadData->TEB + 8) = (DWORD)pStackData;

	CPU_UnlockThreadList();

	// set initial stack ptr
	pCpuThreadData->CpuState.dwRegister[CPU_GetRegisterIndexByName("sp")] = (DWORD)pStackData + dwStackSize;

	return 0;
}
