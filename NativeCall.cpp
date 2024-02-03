#include <stdio.h>
#include <windows.h>
#include "WoWMIPS.h"

BYTE *pGlobal_OriginalImageBase = NULL;
LDR_DATA_TABLE_ENTRY *pGlobal_MainExeLdrDataTableEntry = NULL;
void *pGlobal_NativeCallExceptionHandler = NULL;
DWORD (*pGlobal_ExecuteNativeGateway)(DWORD dwTargetAddress, DWORD *pdwParamValueList, DWORD dwParamValueCount) = NULL;

DWORD EmulateCallback(DWORD *pdwParamList, DWORD dwParamCount)
{
	CpuThreadDataStruct *pCpuThreadData = NULL;
	DWORD dwReturnValue = 0;

	// get current thread data
	pCpuThreadData = CPU_GetThreadData();
	if(pCpuThreadData == NULL)
	{
		CPU_Error(NULL);
		return 1;
	}

	// execute callback
	if(CPU_ExecuteSubroutine(pCpuThreadData->pNextCallbackAddress, pdwParamList, dwParamCount, &dwReturnValue) != 0)
	{
		CPU_Error(NULL);
		return 1;
	}

	return dwReturnValue;
}

DWORD WINAPI EmulateCallback_STDCALL_1(DWORD dwValue1)
{
	DWORD dwParamList[1];

	dwParamList[0] = dwValue1;
	return EmulateCallback(dwParamList, 1);
}

DWORD WINAPI EmulateCallback_STDCALL_3(DWORD dwValue1, DWORD dwValue2, DWORD dwValue3)
{
	DWORD dwParamList[3];

	dwParamList[0] = dwValue1;
	dwParamList[1] = dwValue2;
	dwParamList[2] = dwValue3;
	return EmulateCallback(dwParamList, 3);
}

DWORD WINAPI EmulateCallback_STDCALL_4(DWORD dwValue1, DWORD dwValue2, DWORD dwValue3, DWORD dwValue4)
{
	DWORD dwParamList[4];

	dwParamList[0] = dwValue1;
	dwParamList[1] = dwValue2;
	dwParamList[2] = dwValue3;
	dwParamList[3] = dwValue4;
	return EmulateCallback(dwParamList, 4);
}

DWORD EmulateCallback_CDECL_0()
{
	return EmulateCallback(NULL, 0);
}

DWORD NativeCall_GetNativeCallbackAddress(char *pLastNativeCallFunctionName, DWORD dwReturnAddress, DWORD *pdwNativeAddress)
{
	DWORD dwNativeAddress = 0;

	// check callback type
	if(strcmp(pLastNativeCallFunctionName, "_initterm") == 0)
	{
		// initterm callback, initialises class constructors etc. no params, cdecl.
		dwNativeAddress = (DWORD)EmulateCallback_CDECL_0;
	}
	else if(strcmp(pLastNativeCallFunctionName, "LineDDA") == 0)
	{
		// LineDDA_Callback(x, x, x)
		dwNativeAddress = (DWORD)EmulateCallback_STDCALL_3;
	}
	else if(CheckAddressInModule("user32.dll", (BYTE*)dwReturnAddress) == 0)
	{
		// unknown callback type - check if the return address exists within user32.dll - if so, it is probably a generic WNDPROC-style function.
		// this is a more reliable check than comparing the stored module name in szCurrNativeCall because various internal DLLs (comdlg32, shell32, etc) execute user-callbacks via user32!__InternalCallWinProc
		dwNativeAddress = (DWORD)EmulateCallback_STDCALL_4;
	}
	else if(CheckAddressInModule("comdlg32.dll", (BYTE*)dwReturnAddress) == 0)
	{
		// WndProc(x, x, x, x)
		dwNativeAddress = (DWORD)EmulateCallback_STDCALL_4;
	}
	else if(CheckAddressInModule("olesvr32.dll", (BYTE*)dwReturnAddress) == 0)
	{
		// olesvr32!Release(x)
		dwNativeAddress = (DWORD)EmulateCallback_STDCALL_1;
	}
	else
	{
		return 1;
	}

	*pdwNativeAddress = dwNativeAddress;

	return 0;
}

DWORD WINAPI NativeCall_ExceptionHandler(EXCEPTION_POINTERS *pExceptionInfo)
{
	CpuThreadDataStruct *pCpuThreadData = NULL;
	char *pLastNativeCallFunctionName = NULL;
	DWORD dwNativeAddress = 0;
	DWORD dwReturnAddress = 0;

	// caught exception - check type
	if(pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		// check if the native instruction pointer is within the MIPS executable
		if(pExceptionInfo->ContextRecord->Eip >= (DWORD)pGlobal_ImageBase && pExceptionInfo->ContextRecord->Eip < ((DWORD)pGlobal_ImageBase + dwGlobal_ImageSize))
		{
			// something attempted to execute MIPS code directly, emulate the MIPS callback code
			pCpuThreadData = CPU_GetThreadData();
			if(pCpuThreadData == NULL)
			{
				// initialise new thread
				if(CPU_InitialiseThread() != 0)
				{
					// failed to initialise new thread (CPU state not initialised)
					CPU_Error(NULL);
				}

				// store original instruction pointer
				pCpuThreadData->pNextCallbackAddress = (BYTE*)pExceptionInfo->ContextRecord->Eip;

				// call thread entry-point
				pExceptionInfo->ContextRecord->Eip = (DWORD)EmulateCallback_STDCALL_1;
			}
			else
			{
				// get return address
				dwReturnAddress = *(DWORD*)pExceptionInfo->ContextRecord->Esp;

				if(dwGlobal_DebugMode != 0)
				{
					printf("          <Callback caught at 0x%08X - return address: 0x%08X>\n", pExceptionInfo->ContextRecord->Eip, dwReturnAddress);
				}

				// store original instruction pointer
				pCpuThreadData->pNextCallbackAddress = (BYTE*)pExceptionInfo->ContextRecord->Eip;

				pLastNativeCallFunctionName = strstr(pCpuThreadData->szCurrNativeCall, "!");
				if(pLastNativeCallFunctionName == NULL)
				{
					// error
					CPU_SetError(&pCpuThreadData->CpuState, "Invalid callback data");
					CPU_Error(&pCpuThreadData->CpuState);
				}
				pLastNativeCallFunctionName++;

				// check callback type - get native callback function address
				if(NativeCall_GetNativeCallbackAddress(pLastNativeCallFunctionName, dwReturnAddress, &dwNativeAddress) != 0)
				{
					// error
					CPU_SetError(&pCpuThreadData->CpuState, "Unknown callback type");
					CPU_Error(&pCpuThreadData->CpuState);
				}

				pExceptionInfo->ContextRecord->Eip = dwNativeAddress;
			}

			// continue execution
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else
		{
			// check if the native processor is attempting to execute an emulated mips NATIVECALL instruction.
			// this can happen if the emulated code passes an imported function as a parameter to another imported function, for example: CreateDialogParamW(..., DefDlgProcW, ...);
			// this can be recovered by switching execution back to the correct native function.
			if(ValidatePtrRead((BYTE*)pExceptionInfo->ContextRecord->Eip, sizeof(DWORD) * 2) == 0)
			{
				if(*(DWORD*)pExceptionInfo->ContextRecord->Eip == (NATIVECALL_OPCODE << 26))
				{
					// call the native function
					pExceptionInfo->ContextRecord->Eip = *(DWORD*)(pExceptionInfo->ContextRecord->Eip + sizeof(DWORD));

					// continue execution
					return EXCEPTION_CONTINUE_EXECUTION;
				}
			}
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

DWORD NativeCall_ExecuteFunction(CpuStateStruct *pCpuState, char *pFunctionName, DWORD dwFunctionAddress)
{
	DWORD dwParamValues[NATIVECALL_PARAM_COUNT];
	DWORD dwReturnValue = 0;
	BYTE *pStackParamList = NULL;
	DWORD *pdwCurrStackParam = NULL;
	DWORD dwCurrStackParamIndex = 0;
	CpuThreadDataStruct *pCpuThreadData = NULL;
	char szStoredCurrNativeCall[512];

	pCpuThreadData = CPU_GetThreadData();
	if(pCpuThreadData == NULL)
	{
		return 1;
	}

	// get function params
	pStackParamList = (BYTE*)(pCpuState->dwRegister[CPU_GetRegisterIndexByName("sp")] + STACK_HOME_SPACE_BYTES);
	memset((void*)&dwParamValues, 0, sizeof(dwParamValues));
	for(DWORD i = 0; i < NATIVECALL_PARAM_COUNT; i++)
	{
		if(i < 4)
		{
			// first 4 params are stored in registers a0-a3
			dwParamValues[i] = pCpuState->dwRegister[CPU_GetRegisterIndexByName("a0") + i];
		}
		else
		{
			// get next params from the stack
			pdwCurrStackParam = (DWORD*)(pStackParamList + (dwCurrStackParamIndex * sizeof(DWORD)));

			// check if this value is within the stack limits
			if(((BYTE*)pdwCurrStackParam < pCpuThreadData->pStackData) || ((BYTE*)pdwCurrStackParam >= (pCpuThreadData->pStackData + pCpuThreadData->dwStackSize)))
			{
				// out of range
				dwParamValues[i] = 0;
			}
			else
			{
				// read value from stack
				dwParamValues[i] = *pdwCurrStackParam;
			}

			// increase index
			dwCurrStackParamIndex++;
		}
	}

	// store previous value
	memset(szStoredCurrNativeCall, 0, sizeof(szStoredCurrNativeCall));
	strncpy(szStoredCurrNativeCall, pCpuThreadData->szCurrNativeCall, sizeof(szStoredCurrNativeCall) - 1);

	memset(pCpuThreadData->szCurrNativeCall, 0, sizeof(pCpuThreadData->szCurrNativeCall));
	strncpy(pCpuThreadData->szCurrNativeCall, pFunctionName, sizeof(pCpuThreadData->szCurrNativeCall) - 1);

	// call native function
	dwReturnValue = pGlobal_ExecuteNativeGateway(dwFunctionAddress, dwParamValues, NATIVECALL_PARAM_COUNT);

	if(dwGlobal_DebugMode != 0)
	{
		// print return value
		printf("          <%s returned: 0x%08X>\n", pFunctionName, dwReturnValue);
	}

	// restore original value
	memset(pCpuThreadData->szCurrNativeCall, 0, sizeof(pCpuThreadData->szCurrNativeCall));
	strncpy(pCpuThreadData->szCurrNativeCall, szStoredCurrNativeCall, sizeof(pCpuThreadData->szCurrNativeCall) - 1);

	// set return value
	pCpuState->dwRegister[CPU_GetRegisterIndexByName("v0")] = dwReturnValue;

	// update instruction ptr to return address
	pCpuState->pInstructionPtr = (BYTE*)pCpuState->dwRegister[CPU_GetRegisterIndexByName("ra")];
	pCpuState->dwAdvanceInstructionPointer = 0;

	return 0;
}

DWORD NativeCall_InitialiseEnvironment()
{
	PEB *pPEB = NULL;
	BYTE bExecuteNativeGatewayCode[] =
	{
		// push ebp
		0x55,
		// mov ebp, esp
		0x8B, 0xEC,
		// mov ecx, dword ptr [ebp + 0x10] (param count)
		0x8B, 0x4D, 0x10,
		// mov edx, dword ptr [ebp + 0xC] (param list base)
		0x8B, 0x55, 0x0C,
		// lea eax, dword ptr [edx + ecx*4 - 4] (last param in list)
		0x8D, 0x44, 0x8A, 0xFC,

		// loop_start:
		// cmp eax, edx
		0x3B, 0xC2,
		// jb call_function
		0x72, 0x07,
		// push dword ptr [eax]
		0xFF, 0x30,
		// sub eax, 4
		0x83, 0xE8, 0x04,
		// jmp loop_start
		0xEB, 0xF5,

		// call_function:
		// mov eax, dword ptr [ebp + 8] (target function address)
		0x8B, 0x45, 0x08,
		// call eax
		0xFF, 0xD0,
		// mov esp, ebp
		0x8B, 0xE5,
		// pop ebp
		0x5D,
		// ret
		0xC3
	};

	// allocate executable function for nativecall gateway
	pGlobal_ExecuteNativeGateway = (DWORD(*)(DWORD,DWORD*,DWORD))VirtualAlloc(NULL, sizeof(bExecuteNativeGatewayCode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(pGlobal_ExecuteNativeGateway == NULL)
	{
		return 1;
	}
	memcpy((void*)pGlobal_ExecuteNativeGateway, (void*)bExecuteNativeGatewayCode, sizeof(bExecuteNativeGatewayCode));

	// get PEB LDR entry for the main exe image
	pGlobal_MainExeLdrDataTableEntry = GetPebLdrDataTableEntry((BYTE*)GetModuleHandle(NULL));
	if(pGlobal_MainExeLdrDataTableEntry == NULL)
	{
		return 1;
	}

	// update image base address in PEB
	pPEB = GetPeb();
	pGlobal_OriginalImageBase = (BYTE*)pPEB->ImageBase;
	pPEB->ImageBase = (void*)pGlobal_ImageBase;

	// also update the DllBase field within the PEB_LDR table for the main exe.
	// some exes store the module base address and use it to call functions such as GetModuleFileNameW.
	// without this change, the call would fail due to the module base address not being found in the PEB_LDR table.
	pGlobal_MainExeLdrDataTableEntry->DllBase = (void*)pGlobal_ImageBase;

	// install exception handler
	pGlobal_NativeCallExceptionHandler = pRtlAddVectoredExceptionHandler(1, (void*)NativeCall_ExceptionHandler);
	if(pGlobal_NativeCallExceptionHandler == NULL)
	{
		return 1;
	}

	return 0;
}

DWORD NativeCall_RestoreEnvironment()
{
	PEB *pPEB = NULL;

	// remove exception handler
	pRtlRemoveVectoredExceptionHandler(pGlobal_NativeCallExceptionHandler);

	// restore original image base value
	pPEB = GetPeb();
	pGlobal_MainExeLdrDataTableEntry->DllBase = pGlobal_OriginalImageBase;
	pPEB->ImageBase = pGlobal_OriginalImageBase;

	// free execute native gateway function
	VirtualFree(pGlobal_ExecuteNativeGateway, 0, MEM_RELEASE);

	return 0;
}
