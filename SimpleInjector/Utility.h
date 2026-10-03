#pragma once

#include <Windows.h>

typedef struct _PIPE_PAIR {
	HANDLE Server;
	HANDLE Client;
} PIPE_PAIR, * PPIPE_PAIR;

typedef struct _PIPE_AND_ARGUMENT {
	HANDLE Pipe;
	PVOID Argument;
} PIPE_AND_ARGUMENT, * PPIPE_AND_ARGUMENT;

//
// Creates a connected server/client pair of message-mode pipe handles.
//

BOOLEAN
CreateNamedPipeChannel(
	PPIPE_PAIR PipePair
);

//
// Opens an NT object directory (e.g. L"\KnownDlls").
//

HANDLE
OpenDirectoryObject(
	LPCWSTR DirectoryObjectName,
	ULONG DesiredAccess
);
