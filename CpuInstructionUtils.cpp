#include <stdio.h>
#include <windows.h>
#include "WoWMIPS.h"

BYTE *ExecuteInstructionUtils_GetBranchTargetAddress(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	BYTE *pTargetAddress = NULL;
	WORD wOffset = 0;

	// add offset
	if(pDecodedInstruction->pOpcodeType->dwFormat == OPCODE_I_FORMAT)
	{
		wOffset = pDecodedInstruction->IFormat.wImm16;
	}
	else if(pDecodedInstruction->pOpcodeType->dwFormat == OPCODE_REGIMM_FORMAT)
	{
		wOffset = pDecodedInstruction->RegImmFormat.wImm16;
	}
	else
	{
		return NULL;
	}

	// get target address
	pTargetAddress = pCpuState->pInstructionPtr;

	// add delay slot
	pTargetAddress += sizeof(DWORD);

	// add offset
	pTargetAddress += ((DWORD)((short)wOffset)) << 2;

	return pTargetAddress;
}

DWORD ExecuteInstructionUtils_Jump(CpuStateStruct *pCpuState, BYTE bStoreReturnAddressRegisterIndex, BYTE *pJumpDestination)
{
	if(bStoreReturnAddressRegisterIndex != 0)
	{
		// store return address (instruction after the delay slot)
		pCpuState->dwRegister[bStoreReturnAddressRegisterIndex] = (DWORD)pCpuState->pInstructionPtr + (2 * sizeof(DWORD));
	}

	// set jump target
	pCpuState->dwExecutingDelaySlot = 1;
	pCpuState->pJumpAfterDelaySlot = pJumpDestination;

	return 0;
}

DWORD ExecuteInstructionUtils_Branch(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction, DWORD dwConditionMet, BYTE bStoreReturnAddressRegisterIndex, DWORD dwLikely)
{
	BYTE *pTargetAddress = NULL;

	pTargetAddress = ExecuteInstructionUtils_GetBranchTargetAddress(pCpuState, pDecodedInstruction);
	if(pTargetAddress == NULL)
	{
		return 1;
	}

	if(dwConditionMet != 0)
	{
		// set jump target
		ExecuteInstructionUtils_Jump(pCpuState, bStoreReturnAddressRegisterIndex, pTargetAddress);
	}
	else
	{
		if(dwLikely != 0)
		{
			// condition not met - ignore delay slot instruction
			pCpuState->pInstructionPtr += (2 * sizeof(DWORD));
			pCpuState->dwAdvanceInstructionPointer = 0;
		}
	}

	return 0;
}

BYTE *ExecuteInstructionUtils_GetIFormatAddress(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if(pDecodedInstruction->pOpcodeType->dwFormat == OPCODE_I_FORMAT)
	{
		return (BYTE*)(pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegSource] + (DWORD)((short)pDecodedInstruction->IFormat.wImm16));
	}

	return NULL;
}

DWORD ExecuteInstructionUtils_SetResult(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction, DWORD dwResultValue)
{
	if(pDecodedInstruction->pOpcodeType->dwFormat == OPCODE_R_FORMAT)
	{
		pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegDest] = dwResultValue;
	}
	else if(pDecodedInstruction->pOpcodeType->dwFormat == OPCODE_I_FORMAT)
	{
		pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegDest] = dwResultValue;
	}
	else
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstructionUtils_SetIfLessThan(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction, DWORD dwValue1, DWORD dwValue2, DWORD dwSignedCompare)
{
	DWORD dwResult = 0;

	if(dwSignedCompare != 0)
	{
		// signed compare
		if((int)dwValue1 < (int)dwValue2)
		{
			dwResult = 1;
		}
	}
	else
	{
		// unsigned compare
		if(dwValue1 < dwValue2)
		{
			dwResult = 1;
		}
	}

	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, dwResult);

	return 0;
}

DWORD ExecuteInstructionUtils_CompareSignBits(DWORD dwValue1, DWORD dwValue2)
{
	if(((dwValue1 >> 31) & 1) != ((dwValue2 >> 31) & 1))
	{
		// sign bit is different
		return 1;
	}

	return 0;
}

DWORD ExecuteInstructionUtils_ReadMemory(BYTE *pMemoryAddr, DWORD *pdwValue, DWORD dwLength, DWORD dwSignExtend)
{
	DWORD dwValue = 0;

	// validate read ptr
	if(ValidatePtrRead(pMemoryAddr, dwLength) != 0)
	{
		return 1;
	}

	if(dwLength == sizeof(DWORD))
	{
		dwValue = *(DWORD*)pMemoryAddr;
	}
	else if(dwLength == sizeof(WORD))
	{
		if(dwSignExtend == 0)
		{
			dwValue = *(WORD*)pMemoryAddr;
		}
		else
		{
			dwValue = (DWORD)*(short*)pMemoryAddr;
		}
	}
	else if(dwLength == sizeof(BYTE))
	{
		if(dwSignExtend == 0)
		{
			dwValue = *(BYTE*)pMemoryAddr;
		}
		else
		{
			dwValue = (DWORD)*(char*)pMemoryAddr;
		}
	}
	else
	{
		return 1;
	}

	*pdwValue = dwValue;

	return 0;
}

DWORD ExecuteInstructionUtils_WriteMemory(BYTE *pMemoryAddr, DWORD dwValue, DWORD dwLength)
{
	BYTE *pAlignedAddress = NULL;

	// validate write ptr
	if(ValidatePtrWrite(pMemoryAddr, dwLength) != 0)
	{
		return 1;
	}

	CPU_LockThreadList();

	if(dwLength == sizeof(DWORD))
	{
		*(DWORD*)pMemoryAddr = dwValue;
	}
	else if(dwLength == sizeof(WORD))
	{
		*(WORD*)pMemoryAddr = (WORD)dwValue;
	}
	else if(dwLength == sizeof(BYTE))
	{
		*(BYTE*)pMemoryAddr = (BYTE)dwValue;
	}
	else
	{
		CPU_UnlockThreadList();
		return 1;
	}

	// get 4-byte aligned address
	pAlignedAddress = (BYTE*)((DWORD)pMemoryAddr & 0xFFFFFFFC);

	// check is this address is being watched for writes
	for(DWORD i = 0; i < MAX_CPU_THREAD_COUNT; i++)
	{
		if(Global_CpuThreadList[i].dwInUse == 0)
		{
			continue;
		}

		if(Global_CpuThreadList[i].pWatchWritePtr == pAlignedAddress)
		{
			// write detected on a watched address
			Global_CpuThreadList[i].dwWatchWriteDetected = 1;
		}
	}

	CPU_UnlockThreadList();

	return 0;
}

DWORD ExecuteInstructionUtils_Load(CpuStateStruct *pCpuState, BYTE *pMemoryAddr, BYTE bRegisterIndex, DWORD dwLength, DWORD dwSignExtend)
{
	CpuThreadDataStruct *pCpuThreadData = NULL;

	// MIPS programs access the current TEB via USPCR->Teb which exists at 0x7FFFF4A8 - redirect this pointer value to emulated TEB structure
	if(pMemoryAddr == (BYTE*)0x7FFFF4A8 && dwLength == 4)
	{
		pCpuThreadData = CPU_GetThreadData();
		if(pCpuThreadData == NULL)
		{
			return 1;
		}

		pCpuState->dwRegister[bRegisterIndex] = (DWORD)&pCpuThreadData->TEB;
	}
	else
	{
		if(ExecuteInstructionUtils_ReadMemory(pMemoryAddr, &pCpuState->dwRegister[bRegisterIndex], dwLength, dwSignExtend) != 0)
		{
			CPU_SetError(pCpuState, "Failed to read memory (0x%08X)", pMemoryAddr);
			return 1;
		}
	}

	return 0;
}

DWORD ExecuteInstructionUtils_Store(CpuStateStruct *pCpuState, BYTE *pMemoryAddr, BYTE bRegisterIndex, DWORD dwLength)
{
	if(ExecuteInstructionUtils_WriteMemory(pMemoryAddr, pCpuState->dwRegister[bRegisterIndex], dwLength) != 0)
	{
		CPU_SetError(pCpuState, "Failed to write memory (0x%08X)", pMemoryAddr);
		return 1;
	}

	return 0;
}

DWORD ExecuteInstructionUtils_LoadStoreUnaligned(CpuStateStruct *pCpuState, BYTE *pMemoryAddr, BYTE bRegisterIndex, DWORD dwLeft, DWORD dwStore)
{
	BYTE *pCurrPtr_Memory = NULL;
	BYTE *pCurrPtr_Register = NULL;
	DWORD dwBoundaryIndex = 0;
	DWORD dwReadMemoryValue = 0;

	pCurrPtr_Memory = pMemoryAddr;
	if(dwLeft == 0)
	{
		pCurrPtr_Register = (BYTE*)&pCpuState->dwRegister[bRegisterIndex];
		dwBoundaryIndex = 0;
	}
	else
	{
		pCurrPtr_Register = (BYTE*)&pCpuState->dwRegister[bRegisterIndex] + sizeof(DWORD) - 1;
		dwBoundaryIndex = sizeof(DWORD) - 1;
	}

	for(;;)
	{
		if(dwStore == 0)
		{
			// load byte
			if(ExecuteInstructionUtils_ReadMemory(pCurrPtr_Memory, &dwReadMemoryValue, 1, 0) != 0)
			{
				CPU_SetError(pCpuState, "Failed to read memory (0x%08X)", pCurrPtr_Memory);
				return 1;
			}
			*pCurrPtr_Register = (BYTE)dwReadMemoryValue;
		}
		else
		{
			// store byte
			if(ExecuteInstructionUtils_WriteMemory(pCurrPtr_Memory, (DWORD)*pCurrPtr_Register, 1) != 0)
			{
				CPU_SetError(pCpuState, "Failed to write memory (0x%08X)", pCurrPtr_Memory);
				return 1;
			}
		}

		if(dwLeft == 0)
		{
			pCurrPtr_Register++;
			pCurrPtr_Memory++;
		}
		else
		{
			pCurrPtr_Register--;
			pCurrPtr_Memory--;
		}

		// check if we have crossed into the next/previous 32-bit value
		if(((DWORD)pCurrPtr_Memory % sizeof(DWORD)) == dwBoundaryIndex)
		{
			break;
		}
	}

	return 0;
}

DWORD ExecuteInstructionUtils_LoadStoreAtomic(CpuStateStruct *pCpuState, BYTE *pMemoryAddr, BYTE bRegisterIndex, DWORD dwStore)
{
	CpuThreadDataStruct *pCpuThreadData = NULL;

	// ensure address is aligned
	if(((DWORD)pMemoryAddr % sizeof(DWORD)) != 0)
	{
		return 1;
	}

	pCpuThreadData = CPU_GetThreadData();
	if(pCpuThreadData == NULL)
	{
		return 1;
	}

	CPU_LockThreadList();

	if(dwStore == 0)
	{
		// load current value
		if(ExecuteInstructionUtils_Load(pCpuState, pMemoryAddr, bRegisterIndex, 4, 0) != 0)
		{
			CPU_UnlockThreadList();
			return 1;
		}

		// watch pointer for writes
		pCpuThreadData->pWatchWritePtr = pMemoryAddr;
		pCpuThreadData->dwWatchWriteDetected = 0;
	}
	else
	{
		// ensure address matches value from previous LL instruction
		if(pMemoryAddr != pCpuThreadData->pWatchWritePtr)
		{
			// invalid address - failed
			CPU_UnlockThreadList();
			return 1;
		}
		else
		{
			// check if the address has been written to since the previous LL instruction
			if(pCpuThreadData->dwWatchWriteDetected != 0)
			{
				// write detected - failed
				CPU_UnlockThreadList();
				return 1;
			}
			else
			{
				// success - store value
				if(ExecuteInstructionUtils_Store(pCpuState, pMemoryAddr, bRegisterIndex, 4) != 0)
				{
					CPU_UnlockThreadList();
					return 1;
				}
			}
		}

		// reset values
		pCpuThreadData->pWatchWritePtr = NULL;
		pCpuThreadData->dwWatchWriteDetected = 0;
	}

	CPU_UnlockThreadList();

	return 0;
}

DWORD ExecuteInstructionUtils_Divide(CpuStateStruct *pCpuState, BYTE bRegisterIndex1, BYTE bRegisterIndex2, DWORD dwSigned)
{
	DWORD dwRegisterValue1 = 0;
	DWORD dwRegisterValue2 = 0;

	dwRegisterValue1 = pCpuState->dwRegister[bRegisterIndex1];
	dwRegisterValue2 = pCpuState->dwRegister[bRegisterIndex2];

	// prevent divide by zero
	if(dwRegisterValue2 == 0)
	{
		CPU_SetError(pCpuState, "Divide by zero");
		return 1;
	}

	if(dwSigned == 0)
	{
		pCpuState->dwLO = dwRegisterValue1 / dwRegisterValue2;
		pCpuState->dwHI = dwRegisterValue1 % dwRegisterValue2;
	}
	else
	{
		pCpuState->dwLO = (DWORD)((int)dwRegisterValue1 / (int)dwRegisterValue2);
		pCpuState->dwHI = (DWORD)((int)dwRegisterValue1 % (int)dwRegisterValue2);
	}

	return 0;
}

DWORD ExecuteInstructionUtils_Multiply(CpuStateStruct *pCpuState, BYTE bRegisterIndex1, BYTE bRegisterIndex2, DWORD dwSigned)
{
	QWORD qwResult = 0;

	if(dwSigned == 0)
	{
		qwResult = (QWORD)pCpuState->dwRegister[bRegisterIndex1] * (QWORD)pCpuState->dwRegister[bRegisterIndex2];
	}
	else
	{
		qwResult = (QWORD)((__int64)pCpuState->dwRegister[bRegisterIndex1] * (__int64)pCpuState->dwRegister[bRegisterIndex2]);
	}

	pCpuState->dwLO = (DWORD)qwResult;
	pCpuState->dwHI = (DWORD)(qwResult >> 32);

	return 0;
}
