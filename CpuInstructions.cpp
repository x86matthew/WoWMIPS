#include <stdio.h>
#include <windows.h>
#include "WoWMIPS.h"

DWORD ExecuteInstruction_NATIVECALL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwFunctionAddress = 0;
	char *pFunctionName = NULL;

	// get function addr
	dwFunctionAddress = *(DWORD*)((BYTE*)pCpuState->pInstructionPtr + sizeof(DWORD));
	if(dwFunctionAddress == 0)
	{
		// native function not found
		return 1;
	}

	// get function name
	pFunctionName = (char*)((BYTE*)pCpuState->pInstructionPtr + (2 * sizeof(DWORD)));

	// execute native function
	if(NativeCall_ExecuteFunction(pCpuState, pFunctionName, dwFunctionAddress) != 0)
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_BNE(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwConditionMet = 0;

	if(pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegSource] != pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegDest])
	{
		dwConditionMet = 1;
	}

	ExecuteInstructionUtils_Branch(pCpuState, pDecodedInstruction, dwConditionMet, 0, 0);

	return 0;
}

DWORD ExecuteInstruction_BEQ(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwConditionMet = 0;

	if(pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegSource] == pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegDest])
	{
		dwConditionMet = 1;
	}

	ExecuteInstructionUtils_Branch(pCpuState, pDecodedInstruction, dwConditionMet, 0, 0);

	return 0;
}

DWORD ExecuteInstruction_BLEZ(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwConditionMet = 0;

	if((int)pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegSource] <= 0)
	{
		dwConditionMet = 1;
	}

	ExecuteInstructionUtils_Branch(pCpuState, pDecodedInstruction, dwConditionMet, 0, 0);

	return 0;
}

DWORD ExecuteInstruction_BGTZ(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwConditionMet = 0;

	if((int)pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegSource] > 0)
	{
		dwConditionMet = 1;
	}

	ExecuteInstructionUtils_Branch(pCpuState, pDecodedInstruction, dwConditionMet, 0, 0);

	return 0;
}

DWORD ExecuteInstruction_BGTZL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwConditionMet = 0;

	if((int)pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegSource] > 0)
	{
		dwConditionMet = 1;
	}

	ExecuteInstructionUtils_Branch(pCpuState, pDecodedInstruction, dwConditionMet, 0, 1);

	return 0;
}

DWORD ExecuteInstruction_BLTZ(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwConditionMet = 0;

	if((int)pCpuState->dwRegister[pDecodedInstruction->RegImmFormat.bRegSource] < 0)
	{
		dwConditionMet = 1;
	}

	ExecuteInstructionUtils_Branch(pCpuState, pDecodedInstruction, dwConditionMet, 0, 0);

	return 0;
}

DWORD ExecuteInstruction_BLTZAL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwConditionMet = 0;

	if((int)pCpuState->dwRegister[pDecodedInstruction->RegImmFormat.bRegSource] < 0)
	{
		dwConditionMet = 1;
	}

	ExecuteInstructionUtils_Branch(pCpuState, pDecodedInstruction, dwConditionMet, CPU_GetRegisterIndexByName("ra"), 0);

	return 0;
}

DWORD ExecuteInstruction_BLTZALL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwConditionMet = 0;

	if((int)pCpuState->dwRegister[pDecodedInstruction->RegImmFormat.bRegSource] < 0)
	{
		dwConditionMet = 1;
	}

	ExecuteInstructionUtils_Branch(pCpuState, pDecodedInstruction, dwConditionMet, CPU_GetRegisterIndexByName("ra"), 1);

	return 0;
}

DWORD ExecuteInstruction_BGEZ(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwConditionMet = 0;

	if((int)pCpuState->dwRegister[pDecodedInstruction->RegImmFormat.bRegSource] >= 0)
	{
		dwConditionMet = 1;
	}

	ExecuteInstructionUtils_Branch(pCpuState, pDecodedInstruction, dwConditionMet, 0, 0);

	return 0;
}

DWORD ExecuteInstruction_BGEZAL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwConditionMet = 0;

	if((int)pCpuState->dwRegister[pDecodedInstruction->RegImmFormat.bRegSource] >= 0)
	{
		dwConditionMet = 1;
	}

	ExecuteInstructionUtils_Branch(pCpuState, pDecodedInstruction, dwConditionMet, CPU_GetRegisterIndexByName("ra"), 0);

	return 0;
}

DWORD ExecuteInstruction_BGEZALL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwConditionMet = 0;

	if((int)pCpuState->dwRegister[pDecodedInstruction->RegImmFormat.bRegSource] >= 0)
	{
		dwConditionMet = 1;
	}

	ExecuteInstructionUtils_Branch(pCpuState, pDecodedInstruction, dwConditionMet, CPU_GetRegisterIndexByName("ra"), 1);

	return 0;
}

DWORD ExecuteInstruction_BGEZL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwConditionMet = 0;

	if((int)pCpuState->dwRegister[pDecodedInstruction->RegImmFormat.bRegSource] >= 0)
	{
		dwConditionMet = 1;
	}

	ExecuteInstructionUtils_Branch(pCpuState, pDecodedInstruction, dwConditionMet, 0, 1);

	return 0;
}

DWORD ExecuteInstruction_BLTZL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwConditionMet = 0;

	if((int)pCpuState->dwRegister[pDecodedInstruction->RegImmFormat.bRegSource] < 0)
	{
		dwConditionMet = 1;
	}

	ExecuteInstructionUtils_Branch(pCpuState, pDecodedInstruction, dwConditionMet, 0, 1);

	return 0;
}

DWORD ExecuteInstruction_BNEL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwConditionMet = 0;

	if(pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegSource] != pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegDest])
	{
		dwConditionMet = 1;
	}

	ExecuteInstructionUtils_Branch(pCpuState, pDecodedInstruction, dwConditionMet, 0, 1);

	return 0;
}

DWORD ExecuteInstruction_BEQL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwConditionMet = 0;

	if(pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegSource] == pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegDest])
	{
		dwConditionMet = 1;
	}

	ExecuteInstructionUtils_Branch(pCpuState, pDecodedInstruction, dwConditionMet, 0, 1);

	return 0;
}

DWORD ExecuteInstruction_BLEZL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwConditionMet = 0;

	if((int)pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegSource] <= 0)
	{
		dwConditionMet = 1;
	}

	ExecuteInstructionUtils_Branch(pCpuState, pDecodedInstruction, dwConditionMet, 0, 1);

	return 0;
}

DWORD ExecuteInstruction_JALR(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_Jump(pCpuState, pDecodedInstruction->RFormat.bRegDest, (BYTE*)pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource]);

	return 0;
}

DWORD ExecuteInstruction_JAL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_Jump(pCpuState, CPU_GetRegisterIndexByName("ra"), (BYTE*)pDecodedInstruction->JFormat.dwAddress);

	return 0;
}

DWORD ExecuteInstruction_J(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_Jump(pCpuState, 0, (BYTE*)pDecodedInstruction->JFormat.dwAddress);

	return 0;
}

DWORD ExecuteInstruction_JR(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_Jump(pCpuState, 0, (BYTE*)pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource]);

	return 0;
}

DWORD ExecuteInstruction_LUI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, (DWORD)pDecodedInstruction->IFormat.wImm16 << 16);

	return 0;
}

DWORD ExecuteInstruction_LB(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if(ExecuteInstructionUtils_Load(pCpuState, ExecuteInstructionUtils_GetIFormatAddress(pCpuState, pDecodedInstruction), pDecodedInstruction->IFormat.bRegDest, 1, 1) != 0)
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_LBU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if(ExecuteInstructionUtils_Load(pCpuState, ExecuteInstructionUtils_GetIFormatAddress(pCpuState, pDecodedInstruction), pDecodedInstruction->IFormat.bRegDest, 1, 0) != 0)
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_LH(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if(ExecuteInstructionUtils_Load(pCpuState, ExecuteInstructionUtils_GetIFormatAddress(pCpuState, pDecodedInstruction), pDecodedInstruction->IFormat.bRegDest, 2, 1) != 0)
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_LHU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if(ExecuteInstructionUtils_Load(pCpuState, ExecuteInstructionUtils_GetIFormatAddress(pCpuState, pDecodedInstruction), pDecodedInstruction->IFormat.bRegDest, 2, 0) != 0)
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_LW(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if(ExecuteInstructionUtils_Load(pCpuState, ExecuteInstructionUtils_GetIFormatAddress(pCpuState, pDecodedInstruction), pDecodedInstruction->IFormat.bRegDest, 4, 0) != 0)
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_LWL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if(ExecuteInstructionUtils_LoadStoreUnaligned(pCpuState, ExecuteInstructionUtils_GetIFormatAddress(pCpuState, pDecodedInstruction), pDecodedInstruction->IFormat.bRegDest, 1, 0) != 0)
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_LWR(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if(ExecuteInstructionUtils_LoadStoreUnaligned(pCpuState, ExecuteInstructionUtils_GetIFormatAddress(pCpuState, pDecodedInstruction), pDecodedInstruction->IFormat.bRegDest, 0, 0) != 0)
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_SB(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_Store(pCpuState, ExecuteInstructionUtils_GetIFormatAddress(pCpuState, pDecodedInstruction), pDecodedInstruction->IFormat.bRegDest, 1);

	return 0;
}

DWORD ExecuteInstruction_SH(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_Store(pCpuState, ExecuteInstructionUtils_GetIFormatAddress(pCpuState, pDecodedInstruction), pDecodedInstruction->IFormat.bRegDest, 2);

	return 0;
}

DWORD ExecuteInstruction_SW(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_Store(pCpuState, ExecuteInstructionUtils_GetIFormatAddress(pCpuState, pDecodedInstruction), pDecodedInstruction->IFormat.bRegDest, 4);

	return 0;
}

DWORD ExecuteInstruction_SWL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_LoadStoreUnaligned(pCpuState, ExecuteInstructionUtils_GetIFormatAddress(pCpuState, pDecodedInstruction), pDecodedInstruction->IFormat.bRegDest, 1, 1);

	return 0;
}

DWORD ExecuteInstruction_SWR(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_LoadStoreUnaligned(pCpuState, ExecuteInstructionUtils_GetIFormatAddress(pCpuState, pDecodedInstruction), pDecodedInstruction->IFormat.bRegDest, 0, 1);

	return 0;
}

DWORD ExecuteInstruction_SLTI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetIfLessThan(pCpuState, pDecodedInstruction, pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegSource], (DWORD)((short)pDecodedInstruction->IFormat.wImm16), 1);

	return 0;
}

DWORD ExecuteInstruction_SLTIU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetIfLessThan(pCpuState, pDecodedInstruction, pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegSource], (DWORD)((short)pDecodedInstruction->IFormat.wImm16), 0);

	return 0;
}

DWORD ExecuteInstruction_SLT(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetIfLessThan(pCpuState, pDecodedInstruction, pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource], pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget], 1);

	return 0;
}

DWORD ExecuteInstruction_SLTU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetIfLessThan(pCpuState, pDecodedInstruction, pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource], pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget], 0);

	return 0;
}

DWORD ExecuteInstruction_ADDU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource] + pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget]);

	return 0;
}

DWORD ExecuteInstruction_ADDIU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegSource] + (DWORD)((short)pDecodedInstruction->IFormat.wImm16));

	return 0;
}

DWORD ExecuteInstruction_ADD(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwResult = 0;
	
	dwResult = pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource] + pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget];

	// compare sign bit for overflow
	if(ExecuteInstructionUtils_CompareSignBits(dwResult, pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource]) != 0)
	{
		return 1;
	}

	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, dwResult);

	return 0;
}

DWORD ExecuteInstruction_ADDI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwResult = 0;

	dwResult = pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegSource] + (DWORD)((short)pDecodedInstruction->IFormat.wImm16);

	// compare sign bit for overflow
	if(ExecuteInstructionUtils_CompareSignBits(dwResult, pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegSource]) != 0)
	{
		return 1;
	}

	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, dwResult);

	return 0;
}

DWORD ExecuteInstruction_AND(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource] & pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget]);

	return 0;
}

DWORD ExecuteInstruction_ANDI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegSource] & pDecodedInstruction->IFormat.wImm16);

	return 0;
}

DWORD ExecuteInstruction_OR(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource] | pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget]);

	return 0;
}

DWORD ExecuteInstruction_ORI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegSource] | pDecodedInstruction->IFormat.wImm16);

	return 0;
}

DWORD ExecuteInstruction_NOR(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, ~(pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource] | pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget]));

	return 0;
}

DWORD ExecuteInstruction_XOR(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource] ^ pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget]);

	return 0;
}

DWORD ExecuteInstruction_XORI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, pCpuState->dwRegister[pDecodedInstruction->IFormat.bRegSource] ^ pDecodedInstruction->IFormat.wImm16);

	return 0;
}

DWORD ExecuteInstruction_SUB(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwResult = 0;

	dwResult = pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource] - pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget];

	// compare sign bit for overflow
	if(ExecuteInstructionUtils_CompareSignBits(dwResult, pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource]) != 0)
	{
		return 1;
	}

	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, dwResult);

	return 0;
}

DWORD ExecuteInstruction_SUBU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource] - pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget]);

	return 0;
}

DWORD ExecuteInstruction_MULT(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_Multiply(pCpuState, pDecodedInstruction->RFormat.bRegSource, pDecodedInstruction->RFormat.bRegTarget, 1);

	return 0;
}

DWORD ExecuteInstruction_MULTU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_Multiply(pCpuState, pDecodedInstruction->RFormat.bRegSource, pDecodedInstruction->RFormat.bRegTarget, 0);

	return 0;
}

DWORD ExecuteInstruction_DIV(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if(ExecuteInstructionUtils_Divide(pCpuState, pDecodedInstruction->RFormat.bRegSource, pDecodedInstruction->RFormat.bRegTarget, 1) != 0)
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_DIVU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if(ExecuteInstructionUtils_Divide(pCpuState, pDecodedInstruction->RFormat.bRegSource, pDecodedInstruction->RFormat.bRegTarget, 0) != 0)
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_MFLO(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, pCpuState->dwLO);

	return 0;
}

DWORD ExecuteInstruction_MFHI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, pCpuState->dwHI);

	return 0;
}

DWORD ExecuteInstruction_MTLO(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	pCpuState->dwLO = pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource];

	return 0;
}

DWORD ExecuteInstruction_MTHI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	pCpuState->dwHI = pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource];

	return 0;
}

DWORD ExecuteInstruction_SLL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget] << pDecodedInstruction->RFormat.bShiftAmount);

	return 0;
}

DWORD ExecuteInstruction_SRA(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, (int)pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget] >> pDecodedInstruction->RFormat.bShiftAmount);

	return 0;
}

DWORD ExecuteInstruction_SRL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget] >> pDecodedInstruction->RFormat.bShiftAmount);

	return 0;
}

DWORD ExecuteInstruction_SLLV(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget] << (pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource] & 0x1F));

	return 0;
}

DWORD ExecuteInstruction_SRLV(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget] >> (pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource] & 0x1F));

	return 0;
}

DWORD ExecuteInstruction_SRAV(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, (int)pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget] >> (pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource] & 0x1F));

	return 0;
}

DWORD ExecuteInstruction_TGE(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if((int)pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource] >= (int)pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget])
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_TGEU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if(pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource] >= pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget])
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_TLT(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if((int)pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource] < (int)pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget])
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_TLTU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if(pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource] < pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget])
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_TEQ(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if(pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource] == pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget])
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_TNE(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if(pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegSource] != pCpuState->dwRegister[pDecodedInstruction->RFormat.bRegTarget])
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_TGEI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if((int)pCpuState->dwRegister[pDecodedInstruction->RegImmFormat.bRegSource] >= (int)((short)pDecodedInstruction->RegImmFormat.wImm16))
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_TGEIU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if(pCpuState->dwRegister[pDecodedInstruction->RegImmFormat.bRegSource] >= (DWORD)((short)pDecodedInstruction->IFormat.wImm16))
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_TLTI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if((int)pCpuState->dwRegister[pDecodedInstruction->RegImmFormat.bRegSource] < (int)((short)pDecodedInstruction->RegImmFormat.wImm16))
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_TLTIU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if(pCpuState->dwRegister[pDecodedInstruction->RegImmFormat.bRegSource] < (DWORD)((short)pDecodedInstruction->IFormat.wImm16))
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_TEQI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if((int)pCpuState->dwRegister[pDecodedInstruction->RegImmFormat.bRegSource] == (int)((short)pDecodedInstruction->RegImmFormat.wImm16))
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_TNEI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if((int)pCpuState->dwRegister[pDecodedInstruction->RegImmFormat.bRegSource] != (int)((short)pDecodedInstruction->RegImmFormat.wImm16))
	{
		return 1;
	}

	return 0;
}

DWORD ExecuteInstruction_LL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	ExecuteInstructionUtils_LoadStoreAtomic(pCpuState, ExecuteInstructionUtils_GetIFormatAddress(pCpuState, pDecodedInstruction), pDecodedInstruction->IFormat.bRegDest, 0);

	return 0;
}

DWORD ExecuteInstruction_SC(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	if(ExecuteInstructionUtils_LoadStoreAtomic(pCpuState, ExecuteInstructionUtils_GetIFormatAddress(pCpuState, pDecodedInstruction), pDecodedInstruction->IFormat.bRegDest, 1) != 0)
	{
		// atomic store failed
		ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, 0);
	}
	else
	{
		// success
		ExecuteInstructionUtils_SetResult(pCpuState, pDecodedInstruction, 1);
	}

	return 0;
}
