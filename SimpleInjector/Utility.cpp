#include "Utility.h"

#include "Log.h"
#include "NtDefines.h"

#include <Windows.h>
#include <stdio.h>

BOOLEAN
CreateNamedPipeChannel(
	PPIPE_PAIR PipePair
)
{
	// A per-process unique name keeps concurrent injector instances
	// from colliding on the same pipe.
	WCHAR PipeName[MAX_PATH];
	swprintf_s(PipeName, MAX_PATH, L"\\\\.\\pipe\\SimpleInjector_%lu", GetCurrentProcessId());

	PipePair->Server = CreateNamedPipeW(
		PipeName,
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		1,
		0x10000,
		0x10000,
		0,
		NULL
	);

	if (PipePair->Server == INVALID_HANDLE_VALUE) {
		ErrorLog(L"Failed to create named pipe server end.");
	}

	PipePair->Client = CreateFileW(
		PipeName,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);

	if (PipePair->Client == INVALID_HANDLE_VALUE) {
		ErrorLog(L"Failed to connect client end of the pipe.");
	}

	return TRUE;
}

HANDLE
OpenDirectoryObject(
	LPCWSTR DirectoryObjectName,
	ULONG DesiredAccess
)
{
	UNICODE_STRING ObjectName = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	HANDLE DirectoryObjectHandle = NULL;

	RtlInitUnicodeString(&ObjectName, DirectoryObjectName);
	InitializeObjectAttributes(&ObjectAttributes, &ObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	NTSTATUS Status = NtOpenDirectoryObject(&DirectoryObjectHandle, DesiredAccess, &ObjectAttributes);

	if (!NT_SUCCESS(Status)) {
		ErrorLog(L"NtOpenDirectoryObject(%s) failed with status 0x%x.", DirectoryObjectName, Status);
	}

	return DirectoryObjectHandle;
}
