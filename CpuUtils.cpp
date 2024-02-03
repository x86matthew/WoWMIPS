#include <stdio.h>
#include <windows.h>
#include "WoWMIPS.h"

char *pGlobal_RegisterNames[REGISTER_COUNT] =
{
	"zero",
	"at",
	"v0",
	"v1",
	"a0",
	"a1",
	"a2",
	"a3",
	"t0",
	"t1",
	"t2",
	"t3",
	"t4",
	"t5",
	"t6",
	"t7",
	"s0",
	"s1",
	"s2",
	"s3",
	"s4",
	"s5",
	"s6",
	"s7",
	"t8",
	"t9",
	"k0",
	"k1",
	"gp",
	"sp",
	"fp",
	"ra",
};

OpcodeTypeStruct Global_OpcodeList[] =
{
	// custom NATIVECALL instruction
	{ "NATIVECALL", OPCODE_I_FORMAT, NATIVECALL_OPCODE, ExecuteInstruction_NATIVECALL },

	// standard MIPS instructions
	{ "ADD", OPCODE_R_FORMAT, 0x20, ExecuteInstruction_ADD },
	{ "ADDI", OPCODE_I_FORMAT, 0x08, ExecuteInstruction_ADDI },
	{ "ADDIU", OPCODE_I_FORMAT, 0x09, ExecuteInstruction_ADDIU },
	{ "ADDU", OPCODE_R_FORMAT, 0x21, ExecuteInstruction_ADDU },
	{ "AND", OPCODE_R_FORMAT, 0x24, ExecuteInstruction_AND },
	{ "ANDI", OPCODE_I_FORMAT, 0x0C, ExecuteInstruction_ANDI },
	{ "BEQ", OPCODE_I_FORMAT, 0x04, ExecuteInstruction_BEQ },
	{ "BEQL", OPCODE_I_FORMAT, 0x14, ExecuteInstruction_BEQL },
	{ "BGEZ", OPCODE_REGIMM_FORMAT, 0x01, ExecuteInstruction_BGEZ },
	{ "BGEZAL", OPCODE_REGIMM_FORMAT, 0x11, ExecuteInstruction_BGEZAL },
	{ "BGEZALL", OPCODE_REGIMM_FORMAT, 0x13, ExecuteInstruction_BGEZALL },
	{ "BGEZL", OPCODE_REGIMM_FORMAT, 0x03, ExecuteInstruction_BGEZL },
	{ "BGTZ", OPCODE_I_FORMAT, 0x07, ExecuteInstruction_BGTZ },
	{ "BGTZL", OPCODE_I_FORMAT, 0x17, ExecuteInstruction_BGTZL },
	{ "BLEZ", OPCODE_I_FORMAT, 0x06, ExecuteInstruction_BLEZ },
	{ "BLEZL", OPCODE_I_FORMAT, 0x16, ExecuteInstruction_BLEZL },
	{ "BLTZ", OPCODE_REGIMM_FORMAT, 0x00, ExecuteInstruction_BLTZ },
	{ "BLTZAL", OPCODE_REGIMM_FORMAT, 0x10, ExecuteInstruction_BLTZAL },
	{ "BLTZALL", OPCODE_REGIMM_FORMAT, 0x12, ExecuteInstruction_BLTZALL },
	{ "BLTZL", OPCODE_REGIMM_FORMAT, 0x02, ExecuteInstruction_BLTZL },
	{ "BNE", OPCODE_I_FORMAT, 0x05, ExecuteInstruction_BNE },
	{ "BNEL", OPCODE_I_FORMAT, 0x15, ExecuteInstruction_BNEL },
	{ "DIV", OPCODE_R_FORMAT, 0x1A, ExecuteInstruction_DIV },
	{ "DIVU", OPCODE_R_FORMAT, 0x1B, ExecuteInstruction_DIVU },
	{ "J", OPCODE_J_FORMAT, 0x02, ExecuteInstruction_J },
	{ "JAL", OPCODE_J_FORMAT, 0x03, ExecuteInstruction_JAL },
	{ "JALR", OPCODE_R_FORMAT, 0x09, ExecuteInstruction_JALR },
	{ "JR", OPCODE_R_FORMAT, 0x08, ExecuteInstruction_JR },
	{ "LB", OPCODE_I_FORMAT, 0x20, ExecuteInstruction_LB },
	{ "LBU", OPCODE_I_FORMAT, 0x24, ExecuteInstruction_LBU },
	{ "LH", OPCODE_I_FORMAT, 0x21, ExecuteInstruction_LH },
	{ "LHU", OPCODE_I_FORMAT, 0x25, ExecuteInstruction_LHU },
	{ "LL", OPCODE_I_FORMAT, 0x30, ExecuteInstruction_LL },
	{ "LUI", OPCODE_I_FORMAT, 0x0F, ExecuteInstruction_LUI },
	{ "LW", OPCODE_I_FORMAT, 0x23, ExecuteInstruction_LW },
	{ "LWL", OPCODE_I_FORMAT, 0x22, ExecuteInstruction_LWL },
	{ "LWR", OPCODE_I_FORMAT, 0x26, ExecuteInstruction_LWR },
	{ "MFHI", OPCODE_R_FORMAT, 0x10, ExecuteInstruction_MFHI },
	{ "MFLO", OPCODE_R_FORMAT, 0x12, ExecuteInstruction_MFLO },
	{ "MTHI", OPCODE_R_FORMAT, 0x11, ExecuteInstruction_MTHI },
	{ "MTLO", OPCODE_R_FORMAT, 0x13, ExecuteInstruction_MTLO },
	{ "MULT", OPCODE_R_FORMAT, 0x18, ExecuteInstruction_MULT },
	{ "MULTU", OPCODE_R_FORMAT, 0x19, ExecuteInstruction_MULTU },
	{ "NOR", OPCODE_R_FORMAT, 0x27, ExecuteInstruction_NOR },
	{ "OR", OPCODE_R_FORMAT, 0x25, ExecuteInstruction_OR },
	{ "ORI", OPCODE_I_FORMAT, 0x0D, ExecuteInstruction_ORI },
	{ "SB", OPCODE_I_FORMAT, 0x28, ExecuteInstruction_SB },
	{ "SC", OPCODE_I_FORMAT, 0x38, ExecuteInstruction_SC },
	{ "SH", OPCODE_I_FORMAT, 0x29, ExecuteInstruction_SH },
	{ "SLL", OPCODE_R_FORMAT, 0x00, ExecuteInstruction_SLL },
	{ "SLLV", OPCODE_R_FORMAT, 0x04, ExecuteInstruction_SLLV },
	{ "SLT", OPCODE_R_FORMAT, 0x2A, ExecuteInstruction_SLT },
	{ "SLTI", OPCODE_I_FORMAT, 0x0A, ExecuteInstruction_SLTI },
	{ "SLTIU", OPCODE_I_FORMAT, 0x0B, ExecuteInstruction_SLTIU },
	{ "SLTU", OPCODE_R_FORMAT, 0x2B, ExecuteInstruction_SLTU },
	{ "SRA", OPCODE_R_FORMAT, 0x03, ExecuteInstruction_SRA },
	{ "SRAV", OPCODE_R_FORMAT, 0x07, ExecuteInstruction_SRAV },
	{ "SRL", OPCODE_R_FORMAT, 0x02, ExecuteInstruction_SRL },
	{ "SRLV", OPCODE_R_FORMAT, 0x06, ExecuteInstruction_SRLV },
	{ "SUB", OPCODE_R_FORMAT, 0x22, ExecuteInstruction_SUB },
	{ "SUBU", OPCODE_R_FORMAT, 0x23, ExecuteInstruction_SUBU },
	{ "SW", OPCODE_I_FORMAT, 0x2B, ExecuteInstruction_SW },
	{ "SWL", OPCODE_I_FORMAT, 0x2A, ExecuteInstruction_SWL },
	{ "SWR", OPCODE_I_FORMAT, 0x2E, ExecuteInstruction_SWR },
	{ "TEQ", OPCODE_R_FORMAT, 0x34, ExecuteInstruction_TEQ },
	{ "TEQI", OPCODE_REGIMM_FORMAT, 0x0C, ExecuteInstruction_TEQI },
	{ "TGE", OPCODE_R_FORMAT, 0x30, ExecuteInstruction_TGE },
	{ "TGEI", OPCODE_REGIMM_FORMAT, 0x08, ExecuteInstruction_TGEI },
	{ "TGEIU", OPCODE_REGIMM_FORMAT, 0x09, ExecuteInstruction_TGEIU },
	{ "TGEU", OPCODE_R_FORMAT, 0x31, ExecuteInstruction_TGEU },
	{ "TLT", OPCODE_R_FORMAT, 0x32, ExecuteInstruction_TLT },
	{ "TLTI", OPCODE_REGIMM_FORMAT, 0x0A, ExecuteInstruction_TLTI },
	{ "TLTIU", OPCODE_REGIMM_FORMAT, 0x0B, ExecuteInstruction_TLTIU },
	{ "TLTU", OPCODE_R_FORMAT, 0x33, ExecuteInstruction_TLTU },
	{ "TNE", OPCODE_R_FORMAT, 0x36, ExecuteInstruction_TNE },
	{ "TNEI", OPCODE_REGIMM_FORMAT, 0x0E, ExecuteInstruction_TNEI },
	{ "XOR", OPCODE_R_FORMAT, 0x26, ExecuteInstruction_XOR },
	{ "XORI", OPCODE_I_FORMAT, 0x0E, ExecuteInstruction_XORI },
};

DWORD CPU_SetError(CpuStateStruct *pCpuState, char *pErrorFormatStr, ...)
{
	va_list ArgList;

	if(pCpuState->dwErrorSet != 0)
	{
		// error already set
		return 1;
	}

	// save formatted error msg
	va_start(ArgList, pErrorFormatStr);
	memset(pCpuState->szErrorMsg, 0, sizeof(pCpuState->szErrorMsg));
	_vsnprintf(pCpuState->szErrorMsg, sizeof(pCpuState->szErrorMsg) - 1, pErrorFormatStr, ArgList);
	va_end(ArgList);

	// set flag
	pCpuState->dwErrorSet = 1;

	return 0;
}

BYTE CPU_GetRegisterIndexByName(char *pRegisterName)
{
	for(DWORD i = 0; i < REGISTER_COUNT; i++)
	{
		if(stricmp(pGlobal_RegisterNames[i], pRegisterName) == 0)
		{
			return (BYTE)i;
		}
	}

	// register name not found - return 0
	return 0;
}

DWORD CPU_DecodeInstruction(DWORD dwInstruction, CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction)
{
	DWORD dwOpcodeCount = 0;
	DWORD dwOpcode = 0;
	DWORD dwRFuncIndex = 0;
	DWORD dwRegImmFuncIndex = 0;
	OpcodeTypeStruct *pOpcodeType = NULL;
	DecodedInstructionStruct DecodedInstruction;
	DWORD dwDelaySlotAddress = 0;

	dwOpcode = dwInstruction >> 26;

	dwOpcodeCount = sizeof(Global_OpcodeList) / sizeof(Global_OpcodeList[0]);
	for(DWORD i = 0; i < dwOpcodeCount; i++)
	{
		// check format
		if(dwOpcode == 0)
		{
			// R-format
			if(Global_OpcodeList[i].dwFormat != OPCODE_R_FORMAT)
			{
				continue;
			}

			// check R-format function index
			dwRFuncIndex = dwInstruction & 0x3F;
			if(dwRFuncIndex == Global_OpcodeList[i].dwOpcodeIndex)
			{
				// found opcode
				pOpcodeType = &Global_OpcodeList[i];
				break;
			}
		}
		else if(dwOpcode == 1)
		{
			// REGIMM format
			if(Global_OpcodeList[i].dwFormat != OPCODE_REGIMM_FORMAT)
			{
				continue;
			}

			// check regimm function index
			dwRegImmFuncIndex = (dwInstruction >> 16) & 0x1F;
			if(dwRegImmFuncIndex == Global_OpcodeList[i].dwOpcodeIndex)
			{
				// found opcode
				pOpcodeType = &Global_OpcodeList[i];
				break;
			}
		}
		else
		{
			// I-format or J-format
			if(Global_OpcodeList[i].dwFormat != OPCODE_I_FORMAT && Global_OpcodeList[i].dwFormat != OPCODE_J_FORMAT)
			{
				continue;
			}

			// check main opcode index
			if(dwOpcode == Global_OpcodeList[i].dwOpcodeIndex)
			{
				// found opcode
				pOpcodeType = &Global_OpcodeList[i];
				break;
			}
		}
	}

	if(pOpcodeType == NULL)
	{
		// opcode not found - set error
		if(dwOpcode == 0)
		{
			dwRFuncIndex = dwInstruction & 0x3F;
			CPU_SetError(pCpuState, "Invalid R_Function Opcode (0x%02X)", dwRFuncIndex);
		}
		else if(dwOpcode == 1)
		{
			dwRegImmFuncIndex = (dwInstruction >> 16) & 0x1F;
			CPU_SetError(pCpuState, "Invalid REGIMM Opcode (0x%02X)", dwRegImmFuncIndex);
		}
		else
		{
			CPU_SetError(pCpuState, "Invalid Opcode (0x%02X)", dwOpcode);
		}

		return 1;
	}

	memset((void*)&DecodedInstruction, 0, sizeof(DecodedInstruction));
	DecodedInstruction.pOpcodeType = pOpcodeType;
	if(pOpcodeType->dwFormat == OPCODE_R_FORMAT)
	{
		DecodedInstruction.RFormat.bRegSource = (BYTE)((dwInstruction >> 21) & 0x1F);
		DecodedInstruction.RFormat.bRegTarget = (BYTE)((dwInstruction >> 16) & 0x1F);
		DecodedInstruction.RFormat.bRegDest = (BYTE)((dwInstruction >> 11) & 0x1F);
		DecodedInstruction.RFormat.bShiftAmount = (BYTE)((dwInstruction >> 6) & 0x1F);
	}
	else if(pOpcodeType->dwFormat == OPCODE_J_FORMAT)
	{
		dwDelaySlotAddress = (DWORD)pCpuState->pInstructionPtr + sizeof(DWORD);
		DecodedInstruction.JFormat.dwAddress = (dwDelaySlotAddress & 0xF0000000) + ((dwInstruction & 0x3FFFFFF) << 2);
	}
	else if(pOpcodeType->dwFormat == OPCODE_I_FORMAT)
	{
		DecodedInstruction.IFormat.bRegSource = (BYTE)((dwInstruction >> 21) & 0x1F);
		DecodedInstruction.IFormat.bRegDest = (BYTE)((dwInstruction >> 16) & 0x1F);
		DecodedInstruction.IFormat.wImm16 = (WORD)(dwInstruction & 0xFFFF);
	}
	else if(pOpcodeType->dwFormat == OPCODE_REGIMM_FORMAT)
	{
		DecodedInstruction.RegImmFormat.bRegSource = (BYTE)((dwInstruction >> 21) & 0x1F);
		DecodedInstruction.RegImmFormat.wImm16 = (WORD)(dwInstruction & 0xFFFF);
	}
	else
	{
		return 1;
	}

	// store data
	memcpy((void*)pDecodedInstruction, (void*)&DecodedInstruction, sizeof(DecodedInstruction));

	return 0;
}

DWORD CPU_PrintInstruction(DecodedInstructionStruct *pDecodedInstruction, CpuStateStruct *pCpuState)
{
	printf("%08X: ", pCpuState->pInstructionPtr);

	if(pDecodedInstruction->pOpcodeType->dwOpcodeIndex == NATIVECALL_OPCODE)
	{
		printf("%s [%s]\n", pDecodedInstruction->pOpcodeType->pOpcodeName, (char*)(pCpuState->pInstructionPtr + sizeof(DWORD) + sizeof(DWORD)));
	}
	else
	{
		if(pDecodedInstruction->pOpcodeType->dwFormat == OPCODE_R_FORMAT)
		{
			printf("%s $%s, $%s, $%s\n", pDecodedInstruction->pOpcodeType->pOpcodeName, pGlobal_RegisterNames[pDecodedInstruction->RFormat.bRegDest], pGlobal_RegisterNames[pDecodedInstruction->RFormat.bRegSource], pGlobal_RegisterNames[pDecodedInstruction->RFormat.bRegTarget]);
		}
		else if(pDecodedInstruction->pOpcodeType->dwFormat == OPCODE_J_FORMAT)
		{
			printf("%s 0x%X\n", pDecodedInstruction->pOpcodeType->pOpcodeName, pDecodedInstruction->JFormat.dwAddress);
		}
		else if(pDecodedInstruction->pOpcodeType->dwFormat == OPCODE_I_FORMAT)
		{
			printf("%s $%s, $%s, 0x%X\n", pDecodedInstruction->pOpcodeType->pOpcodeName, pGlobal_RegisterNames[pDecodedInstruction->IFormat.bRegDest], pGlobal_RegisterNames[pDecodedInstruction->IFormat.bRegSource], pDecodedInstruction->IFormat.wImm16);
		}
		else if(pDecodedInstruction->pOpcodeType->dwFormat == OPCODE_REGIMM_FORMAT)
		{
			printf("%s $%s, 0x%X\n", pDecodedInstruction->pOpcodeType->pOpcodeName, pGlobal_RegisterNames[pDecodedInstruction->RegImmFormat.bRegSource], pDecodedInstruction->RegImmFormat.wImm16);
		}
		else
		{
			return 1;
		}
	}

	return 0;
}

DWORD CPU_Error(CpuStateStruct *pCpuState)
{
	DecodedInstructionStruct DecodedInstruction;
	DWORD dwCurrInstruction = 0;
	DWORD dwOpcode = 0;
	DWORD dwRFuncIndex = 0;
	DWORD dwRegImmFuncIndex = 0;

	printf("\n\n");
	printf("***********************\n");
	printf("*** FATAL CPU ERROR ***\n");
	printf("***********************\n");
	printf("\n");

	if(pCpuState == NULL)
	{
		printf("Error: Failed to initialise thread\n");
	}
	else
	{
		if(pCpuState->dwErrorSet != 0)
		{
			printf("Error: %s\n", pCpuState->szErrorMsg);
		}
		else
		{
			printf("Error: Unknown failure\n");
		}

		printf("\n  ip = 0x%08X\n", pCpuState->pInstructionPtr);
		if(ValidatePtrRead(pCpuState->pInstructionPtr, sizeof(DWORD)) == 0)
		{
			// read current instruction from memory
			dwCurrInstruction = *(DWORD*)pCpuState->pInstructionPtr;

			// decode instruction
			memset((void*)&DecodedInstruction, 0, sizeof(DecodedInstruction));
			if(CPU_DecodeInstruction(dwCurrInstruction, pCpuState, &DecodedInstruction) == 0)
			{
				// print instruction
				printf("\n");
				CPU_PrintInstruction(&DecodedInstruction, pCpuState);
			}
		}

		// print register values
		printf("\n");
		for(DWORD i = 0; i < 16; i++)
		{
			printf("%4s = 0x%08X,   %4s = 0x%08X,\n", pGlobal_RegisterNames[i], pCpuState->dwRegister[i], pGlobal_RegisterNames[16 + i], pCpuState->dwRegister[16 + i]);
		}
		printf("\n");
	}

	// terminate process
	ExitProcess(1);

	return 0;
}

DWORD CPU_Step(CpuStateStruct *pCpuState)
{
	DWORD dwDelaySlot = 0;
	DWORD dwCurrInstruction = 0;
	DecodedInstructionStruct DecodedInstruction;

	// reset error
	pCpuState->dwErrorSet = 0;

	// validate instruction ptr
	if(ValidatePtrRead((BYTE*)pCpuState->pInstructionPtr, sizeof(DWORD)) != 0)
	{
		CPU_SetError(pCpuState, "Failed to read instruction");
		return 1;
	}

	// read current instruction from memory
	dwCurrInstruction = *(DWORD*)pCpuState->pInstructionPtr;

	// decode instruction
	memset((void*)&DecodedInstruction, 0, sizeof(DecodedInstruction));
	if(CPU_DecodeInstruction(dwCurrInstruction, pCpuState, &DecodedInstruction) != 0)
	{
		return 1;
	}

	if(dwGlobal_DebugMode != 0)
	{
		// print instruction
		if(CPU_PrintInstruction(&DecodedInstruction, pCpuState) != 0)
		{
			return 1;
		}
	}

	// reset flag value
	pCpuState->dwAdvanceInstructionPointer = 1;

	// check if this instruction is a delay slot
	dwDelaySlot = 0;
	if(pCpuState->dwExecutingDelaySlot != 0)
	{
		dwDelaySlot = 1;
	}

	// execute instruction
	if(DecodedInstruction.pOpcodeType->pExecuteInstruction(pCpuState, &DecodedInstruction) != 0)
	{
		return 1;
	}

	if(dwDelaySlot != 0)
	{
		// executed delay slot - set instruction pointer to original jump target
		pCpuState->dwExecutingDelaySlot = 0;
		pCpuState->dwAdvanceInstructionPointer = 0;
		pCpuState->pInstructionPtr = pCpuState->pJumpAfterDelaySlot;
	}

	// ensure zero register is always 0
	pCpuState->dwRegister[CPU_GetRegisterIndexByName("zero")] = 0;

	// check if the instruction pointer should be increased
	if(pCpuState->dwAdvanceInstructionPointer != 0)
	{
		pCpuState->pInstructionPtr += sizeof(DWORD);
	}

	return 0;
}

DWORD CPU_ExecuteSubroutine(BYTE *pFunctionAddress, DWORD *pdwParamList, DWORD dwParamCount, DWORD *pdwReturnValue)
{
	CpuThreadDataStruct *pCpuThreadData = NULL;
	CpuStateStruct OrigCpuState;
	DWORD dwReturnValue = 0;
	BYTE *pStackParamList = NULL;
	DWORD *pdwCurrStackParam = NULL;
	DWORD dwCurrStackParamIndex = 0;

	pCpuThreadData = CPU_GetThreadData();
	if(pCpuThreadData == NULL)
	{
		return 1;
	}

	// store original CPU state
	memcpy((void*)&OrigCpuState, (void*)&pCpuThreadData->CpuState, sizeof(OrigCpuState));

	// reserve 16 bytes "home space" on stack
	pCpuThreadData->CpuState.dwRegister[CPU_GetRegisterIndexByName("sp")] -= STACK_HOME_SPACE_BYTES;

	if(dwParamCount > 4)
	{
		// reserve param value space on stack
		pCpuThreadData->CpuState.dwRegister[CPU_GetRegisterIndexByName("sp")] -= ((dwParamCount - 4) * sizeof(DWORD));
	}

	pStackParamList = (BYTE*)(pCpuThreadData->CpuState.dwRegister[CPU_GetRegisterIndexByName("sp")] + STACK_HOME_SPACE_BYTES);
	for(DWORD i = 0; i < dwParamCount; i++)
	{
		if(i < 4)
		{
			// first 4 params are stored in registers a0-a3
			pCpuThreadData->CpuState.dwRegister[CPU_GetRegisterIndexByName("a0") + i] = pdwParamList[i];
		}
		else
		{
			// copy param value to stack
			pdwCurrStackParam = (DWORD*)(pStackParamList + (dwCurrStackParamIndex * sizeof(DWORD)));
			*pdwCurrStackParam = pdwParamList[i];

			// increase index
			dwCurrStackParamIndex++;
		}
	}

	pCpuThreadData->CpuState.pInstructionPtr = pFunctionAddress;

	// set the return address of the subroutine to 0xFFFFFFFF
	pCpuThreadData->CpuState.dwRegister[CPU_GetRegisterIndexByName("ra")] = EXEC_SUBROUTINE_RETURN_ADDRESS;

	// execute subroutine
	for(;;)
	{
		// check if the subroutine has returned
		if(pCpuThreadData->CpuState.pInstructionPtr == (BYTE*)EXEC_SUBROUTINE_RETURN_ADDRESS)
		{
			// callback returned - finished
			break;
		}

		// step
		if(CPU_Step(&pCpuThreadData->CpuState) != 0)
		{
			// error
			CPU_SetError(&pCpuThreadData->CpuState, "Instruction error");
			CPU_Error(&pCpuThreadData->CpuState);

			return 1;
		}
	}

	// get subroutine return value
	dwReturnValue = pCpuThreadData->CpuState.dwRegister[CPU_GetRegisterIndexByName("v0")];

	// restore original CPU state
	memcpy((void*)&pCpuThreadData->CpuState, (void*)&OrigCpuState, sizeof(OrigCpuState));

	if(pdwReturnValue != NULL)
	{
		*pdwReturnValue = dwReturnValue;
	}

	return 0;
}
