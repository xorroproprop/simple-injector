#pragma once

#include <Windows.h>

typedef struct _PIPE_AND_ARGUMENT {
	HANDLE Pipe;
	PVOID Argument;
}PIPE_AND_ARGUMENT, * PPIPE_AND_ARGUMENT;


EXTERN_C
__declspec(dllexport) 
ULONG 
Example(
	PPIPE_AND_ARGUMENT Argument
);

EXTERN_C
__declspec(dllexport)
INT
CreateALPCPort(
	LPCWSTR PortName
);