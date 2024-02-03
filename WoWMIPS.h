#ifndef _M_IX86
#error "Must be compiled as 32-bit"
#endif

#define QWORD unsigned __int64

#define REGISTER_COUNT 32

#define OPCODE_R_FORMAT 1
#define OPCODE_J_FORMAT 2
#define OPCODE_I_FORMAT 3
#define OPCODE_REGIMM_FORMAT 4

// 0x3B is an unused opcode
#define NATIVECALL_OPCODE 0x3B

#define NATIVECALL_PARAM_COUNT 16

#define STACK_HOME_SPACE_BYTES 0x10

#define EXEC_SUBROUTINE_RETURN_ADDRESS 0xFFFFFFFF

#define MAX_CPU_THREAD_COUNT 256

struct UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
};

struct PEB_LDR_DATA
{
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
};

struct LDR_DATA_TABLE_ENTRY
{
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID EntryPoint;
	PVOID Reserved3;
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	PVOID Reserved6;
	ULONG TimeDateStamp;
};

struct PEB
{
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[1];
	PVOID ImageBase;
	PEB_LDR_DATA *Ldr;
	// ...
};

struct CpuStateStruct
{
	DWORD dwRegister[REGISTER_COUNT];
	DWORD dwHI;
	DWORD dwLO;

	BYTE *pInstructionPtr;

	DWORD dwAdvanceInstructionPointer;

	DWORD dwExecutingDelaySlot;
	BYTE *pJumpAfterDelaySlot;

	DWORD dwErrorSet;
	char szErrorMsg[64];
};

struct DecodedInstructionStruct;

struct OpcodeTypeStruct
{
	char *pOpcodeName;
	DWORD dwFormat;
	DWORD dwOpcodeIndex;
	DWORD (*pExecuteInstruction)(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
};

struct DecodedInstruction_RFormatStruct
{
	BYTE bRegSource;
	BYTE bRegTarget;
	BYTE bRegDest;
	BYTE bShiftAmount;
};

struct DecodedInstruction_JFormatStruct
{
	DWORD dwAddress;
};

struct DecodedInstruction_IFormatStruct
{
	BYTE bRegSource;
	BYTE bRegDest;
	WORD wImm16;
};

struct DecodedInstruction_RegImmFormatStruct
{
	BYTE bRegSource;
	WORD wImm16;
};

struct DecodedInstructionStruct
{
	OpcodeTypeStruct *pOpcodeType;
	DecodedInstruction_RFormatStruct RFormat;
	DecodedInstruction_JFormatStruct JFormat;
	DecodedInstruction_IFormatStruct IFormat;
	DecodedInstruction_RegImmFormatStruct RegImmFormat;
};

struct MipsTebStruct
{
	BYTE bPadding[0x1000];
};

struct CpuThreadDataStruct
{
	DWORD dwInUse;

	HANDLE hThread;

	CpuStateStruct CpuState;

	BYTE *pStackData;
	DWORD dwStackSize;

	BYTE *pNextCallbackAddress;
	char szCurrNativeCall[512];

	BYTE *pWatchWritePtr;
	DWORD dwWatchWriteDetected;

	MipsTebStruct TEB;
};

extern void* (WINAPI *pRtlAddVectoredExceptionHandler)(DWORD dwFirstHandler, void *pExceptionHandler);
extern DWORD (WINAPI *pRtlRemoveVectoredExceptionHandler)(void *pHandle);
extern BOOL (WINAPI *pSetProcessDEPPolicy)(DWORD dwFlags);
extern DWORD dwGlobal_CpuThreadDataTlsIndex;
extern BYTE *pGlobal_ImageBase;
extern DWORD dwGlobal_ImageSize;
extern IMAGE_NT_HEADERS32 *pGlobal_ImageNtHeader;
extern DWORD NativeCall_ExecuteFunction(CpuStateStruct *pCpuState, char *pFunctionName, DWORD dwFunctionAddress);
extern BYTE CPU_GetRegisterIndexByName(char *pRegisterName);
extern CpuThreadDataStruct *CPU_GetThreadData();
extern DWORD CPU_ExecuteSubroutine(BYTE *pFunctionAddress, DWORD *pdwParamList, DWORD dwParamCount, DWORD *pdwReturnValue);
extern DWORD ExecuteInstruction_NATIVECALL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_ADDIU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SW(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_LUI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_LW(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SLL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_JALR(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_JAL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_JR(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_BNE(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_BEQ(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_LBU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_OR(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_BNEL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SLTI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_ANDI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_LHU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_XORI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SLTIU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_BEQL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_ADDU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SLT(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SLTU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SH(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SUBU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_BLEZ(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_ORI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_MULTU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_MFLO(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_MFHI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SRA(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SB(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_DIV(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_LB(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_BGEZ(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SRL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_XOR(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_AND(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_LH(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_BLEZL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_LWL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_LWR(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_NOR(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_BGEZL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_BLTZ(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_BLTZL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_DIVU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_MTLO(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_MTHI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_MTLO(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_MTHI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SLL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SRA(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SRL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SLLV(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SRLV(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SRAV(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_ADD(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_ADDI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_J(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SUB(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_MULT(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_BLTZAL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_BLTZALL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_BGEZAL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_BGEZALL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_BGTZ(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_BGTZL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SWL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SWR(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_TGE(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_TGEU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_TLT(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_TLTU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_TEQ(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_TNE(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_TGEI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_TGEIU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_TLTI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_TLTIU(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_TEQI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_TNEI(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_LL(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstruction_SC(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD MemoryMapPE(char *pFilePath, BYTE **ppImageBase, IMAGE_NT_HEADERS32 **ppImageNtHeader);
extern DWORD CPU_InitialiseThread();
extern DWORD ExecuteInstructionUtils_Branch(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction, DWORD dwConditionMet, BYTE bStoreReturnAddressRegisterIndex, DWORD dwLikely);
extern DWORD ExecuteInstructionUtils_Jump(CpuStateStruct *pCpuState, BYTE bStoreReturnAddressRegisterIndex, BYTE *pJumpDestination);
extern BYTE *ExecuteInstructionUtils_GetIFormatAddress(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction);
extern DWORD ExecuteInstructionUtils_SetResult(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction, DWORD dwResultValue);
extern DWORD ExecuteInstructionUtils_SetIfLessThan(CpuStateStruct *pCpuState, DecodedInstructionStruct *pDecodedInstruction, DWORD dwValue1, DWORD dwValue2, DWORD dwSignedCompare);
extern DWORD ExecuteInstructionUtils_LoadStoreUnaligned(CpuStateStruct *pCpuState, BYTE *pMemoryAddr, BYTE bRegisterIndex, DWORD dwLeft, DWORD dwStore);
extern DWORD ExecuteInstructionUtils_CompareSignBits(DWORD dwValue1, DWORD dwValue2);
extern DWORD dwGlobal_DebugMode;
extern CRITICAL_SECTION Global_CpuThreadListCriticalSection;
extern CpuThreadDataStruct Global_CpuThreadList[MAX_CPU_THREAD_COUNT];
extern DWORD ExecuteInstructionUtils_Load(CpuStateStruct *pCpuState, BYTE *pMemoryAddr, BYTE bRegisterIndex, DWORD dwLength, DWORD dwSignExtend);
extern DWORD ExecuteInstructionUtils_Store(CpuStateStruct *pCpuState, BYTE *pMemoryAddr, BYTE bRegisterIndex, DWORD dwLength);
extern DWORD CPU_ReadMemory(BYTE *pMemoryAddr, DWORD *pdwValue, DWORD dwLength, DWORD dwSignExtend);
extern DWORD CPU_WriteMemory(BYTE *pMemoryAddr, DWORD dwValue, DWORD dwLength);
extern DWORD ExecuteInstructionUtils_LoadStoreAtomic(CpuStateStruct *pCpuState, BYTE *pMemoryAddr, BYTE bRegisterIndex, DWORD dwStore);
extern DWORD CPU_LockThreadList();
extern DWORD CPU_UnlockThreadList();
extern DWORD FixCommandLine(DWORD dwIgnoreCharacterCount);
extern DWORD ValidatePtrRead(BYTE *pMemory, DWORD dwLength);
extern DWORD ValidatePtrWrite(BYTE *pMemory, DWORD dwLength);
extern DWORD ValidatePtrExec(BYTE *pMemory, DWORD dwLength);
extern DWORD ExecuteInstructionUtils_Divide(CpuStateStruct *pCpuState, BYTE bRegisterIndex1, BYTE bRegisterIndex2, DWORD dwSigned);
extern DWORD ExecuteInstructionUtils_Multiply(CpuStateStruct *pCpuState, BYTE bRegisterIndex1, BYTE bRegisterIndex2, DWORD dwSigned);
extern DWORD CPU_SetError(CpuStateStruct *pCpuState, char *pErrorFormatStr, ...);
extern DWORD CPU_Error(CpuStateStruct *pCpuState);
extern LDR_DATA_TABLE_ENTRY *GetPebLdrDataTableEntry(BYTE *pModuleBase);
extern PEB *GetPeb();
extern DWORD CheckAddressInModule(char *pModuleName, BYTE *pAddress);
extern DWORD HookFunction(BYTE *pFunctionAddr, BYTE *pHookFunctionAddr);
extern DWORD NativeCall_InitialiseEnvironment();
extern DWORD NativeCall_RestoreEnvironment();
