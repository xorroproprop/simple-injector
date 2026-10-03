#include "ExampleDLL.h"
#include "ALPC.h"

#include <stdio.h>

HANDLE GlobalLogPipe = NULL;

//
// Log to the injected pipe if available, otherwise to STDOUT.
//

VOID Log(CONST CHAR* Format, ...)
{
	DWORD Size = 0;
	PCHAR Buffer = NULL;
	va_list args;

	va_start(args, Format);
	Size = _vscprintf(Format, args) + 1;

	Buffer = (PCHAR)LocalAlloc(LPTR, Size);
	if (!Buffer) {
		ExitThread(1);
	}

	vsprintf_s(Buffer, Size, Format, args);
	va_end(args);

	if (GlobalLogPipe) {
		WriteFile(GlobalLogPipe, Buffer, Size, NULL, NULL);
	}
	else {
		printf("%s", Buffer);
	}

	LocalFree((HLOCAL)Buffer);
}

BOOLEAN InitializeLogging(HANDLE ClientPipe)
{
	GlobalLogPipe = ClientPipe;
	return TRUE;
}

//
// Exported example function -- expects a PPIPE_AND_ARGUMENT whose Pipe member
// is the client end of the logging pipe created by the injector.
//

ULONG Example(PPIPE_AND_ARGUMENT Argument)
{
	HANDLE hThread;

	InitializeLogging(Argument->Pipe);

	Log("HELLO\n");
	Log("Creating Port Handle\n");

	hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CreateALPCPort, (LPVOID)L"\\RPC_CONTROL\\DEMO", 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	return -1;
}

INT CreateALPCPort(LPCWSTR PortName)
{
	NTSTATUS status;
	OBJECT_ATTRIBUTES obj;
	UNICODE_STRING iPort;
	HANDLE port;
	ALPC_PORT_ATTRIBUTES serverportAttrib;

	Log("Entering Function\n");

	RtlInitUnicodeString(&iPort, PortName);
	InitializeObjectAttributes(&obj, &iPort, 0, 0, 0);
	RtlSecureZeroMemory(&serverportAttrib, sizeof(serverportAttrib));
	serverportAttrib.MaxMessageLength = MAX_LEN;

	status = NtAlpcCreatePort(&port, &obj, &serverportAttrib);
	Log("[i] NtAlpcCreatePort: 0x%X\n", status);

	return (INT)status;
}
