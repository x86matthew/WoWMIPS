#include <stdio.h>
#include <windows.h>
#include "WoWMIPS.h"

// debug mode
DWORD dwGlobal_DebugMode = 1;

// imported functions
void* (WINAPI *pRtlAddVectoredExceptionHandler)(DWORD dwFirstHandler, void *pExceptionHandler) = NULL;
DWORD (WINAPI *pRtlRemoveVectoredExceptionHandler)(void *pHandle) = NULL;
BOOL (WINAPI *pSetProcessDEPPolicy)(DWORD dwFlags) = NULL;

// TLS index for emulated info storage
DWORD dwGlobal_CpuThreadDataTlsIndex = 0;

// main executable image
BYTE *pGlobal_ImageBase = NULL;
DWORD dwGlobal_ImageSize = 0;
IMAGE_NT_HEADERS32 *pGlobal_ImageNtHeader = NULL;

int main(int argc, char *argv[])
{
	BYTE *pImageBase = NULL;
	IMAGE_NT_HEADERS32 *pImageNtHeader = NULL;
	BYTE *pEntryPoint = NULL;
	char *pTargetPath = NULL;
	char szFullPath[512];
	char *pLastSlash = NULL;
	DWORD dwIgnoreCommandLineCharacterCount = 0;

	if(argc < 2)
	{
		printf("Usage: %s <target_mips_executable_path>\n", argv[0]);
		return 1;
	}

	// get mips executable path
	pTargetPath = argv[1];

	// get RtlAddVectoredExceptionHandler function ptr
	pRtlAddVectoredExceptionHandler = (VOID*(WINAPI*)(DWORD,VOID*))GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlAddVectoredExceptionHandler");
	if(pRtlAddVectoredExceptionHandler == NULL)
	{
		return 1;
	}

	// get RtlRemoveVectoredExceptionHandler function ptr
	pRtlRemoveVectoredExceptionHandler = (DWORD(WINAPI*)(VOID*))GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlRemoveVectoredExceptionHandler");
	if(pRtlRemoveVectoredExceptionHandler == NULL)
	{
		return 1;
	}

	// get SetProcessDEPPolicy function ptr
	pSetProcessDEPPolicy = (BOOL(WINAPI*)(DWORD))GetProcAddress(GetModuleHandle("kernel32.dll"), "SetProcessDEPPolicy");
	if(pSetProcessDEPPolicy == NULL)
	{
		return 1;
	}

	// initialise thread list lock
	InitializeCriticalSection(&Global_CpuThreadListCriticalSection);

	// allocate cpu thread data TLS slot
	dwGlobal_CpuThreadDataTlsIndex = TlsAlloc();
	if(dwGlobal_CpuThreadDataTlsIndex == TLS_OUT_OF_INDEXES)
	{
		return 1;
	}
	
	// ensure DEP is enabled for this process - old compilers (eg msvc++ 6.0) won't set the NX_COMPAT flag in the output exe.
	// this is required to capture user callbacks - an exception handler intercepts native execution within the MIPS executable code and emulates it instead.
	pSetProcessDEPPolicy(1);

	// get full mips executable path
	memset(szFullPath, 0, sizeof(szFullPath));
	if(GetFullPathName(pTargetPath, sizeof(szFullPath) - 1, szFullPath, NULL) == 0)
	{
		return 1;
	}

	// map mips executable into memory
	if(MemoryMapPE(szFullPath, &pImageBase, &pImageNtHeader) != 0)
	{
		printf("Failed to map MIPS executable: %s\n", szFullPath);
		return 1;
	}

	// set CWD to same directory as target mips exe
	pLastSlash = strrchr(szFullPath, '\\');
	if(pLastSlash == NULL)
	{
		return 1;
	}
	*pLastSlash = '\0';
	SetCurrentDirectory(szFullPath);

	// store image info
	pGlobal_ImageBase = pImageBase;
	pGlobal_ImageNtHeader = pImageNtHeader;
	dwGlobal_ImageSize = pImageNtHeader->OptionalHeader.SizeOfImage;

	// fix command-line (hook GetCommandLine globally rather than IAT hook - might be called indirectly via imported CRT functions)
	dwIgnoreCommandLineCharacterCount = strlen(argv[0]);
	if(*(char*)GetCommandLineA() == '\"')
	{
		// ignore quote characters
		dwIgnoreCommandLineCharacterCount += 2;
	}
	if(FixCommandLine(dwIgnoreCommandLineCharacterCount) != 0)
	{
		return 1;
	}

	// initialise current thread
	if(CPU_InitialiseThread() != 0)
	{
		return 1;
	}

	// initialise emulated process environment
	if(NativeCall_InitialiseEnvironment() != 0)
	{
		return 1;
	}

	// begin execution at program entry-point
	pEntryPoint = (BYTE*)((BYTE*)pImageBase + pImageNtHeader->OptionalHeader.AddressOfEntryPoint);
	if(CPU_ExecuteSubroutine(pEntryPoint, NULL, 0, NULL) != 0)
	{
		return 1;
	}

	// restore original environment
	if(NativeCall_RestoreEnvironment() != 0)
	{
		return 1;
	}

	return 0;
}
