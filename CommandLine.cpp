#include <stdio.h>
#include <windows.h>
#include "WoWMIPS.h"

char *pGlobal_FixedCommandLineA = NULL;
wchar_t *pGlobal_FixedCommandLineW = NULL;

LPSTR WINAPI Hook_GetCommandLineA()
{
	return pGlobal_FixedCommandLineA;
}

LPWSTR WINAPI Hook_GetCommandLineW()
{
	return pGlobal_FixedCommandLineW;
}

DWORD FixCommandLine(DWORD dwIgnoreCharacterCount)
{
	// fix command line (ANSI)
	pGlobal_FixedCommandLineA = GetCommandLineA();
	pGlobal_FixedCommandLineA += dwIgnoreCharacterCount;
	for(;;)
	{
		if(*pGlobal_FixedCommandLineA != ' ')
		{
			break;
		}
		pGlobal_FixedCommandLineA++;
	}

	// fix command line (widechar)
	pGlobal_FixedCommandLineW = GetCommandLineW();
	pGlobal_FixedCommandLineW += dwIgnoreCharacterCount;
	for(;;)
	{
		if(*pGlobal_FixedCommandLineW != L' ')
		{
			break;
		}
		pGlobal_FixedCommandLineW++;
	}

	// hook GetCommandLineA
	if(HookFunction((BYTE*)GetCommandLineA, (BYTE*)Hook_GetCommandLineA) != 0)
	{
		return 1;
	}

	// hook GetCommandLineW
	if(HookFunction((BYTE*)GetCommandLineW, (BYTE*)Hook_GetCommandLineW) != 0)
	{
		return 1;
	}

	return 0;
}
