#include "SimpleInjector.h"

#include <Windows.h>
#include <psapi.h>

#include "Log.h"
#include "NtDefines.h"
#include "Utility.h"
#include "Security.h"

#define PROCESS_FULL_ACCESS ( \
	PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | \
	PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION \
)

SimpleInjector::SimpleInjector(DWORD Pid)
{
	this->Pid = Pid;

	this->ProcessHandle = OpenProcess(PROCESS_FULL_ACCESS, FALSE, Pid);
	if (!this->ProcessHandle) {
		ErrorLog(L"Failed to open process %d.", Pid);
	}

	if (!::OpenProcessToken(this->ProcessHandle, TOKEN_QUERY, &this->ProcessTokenHandle)) {
		ErrorLog(L"Failed to open process %d token.", Pid);
	}

	// Security descriptor that grants the target token access to every object we create.
	this->TokenAccessibleSecurityDescriptor = CreateAccessibleSecurityDescriptorFromToken(
		this->ProcessTokenHandle,
		GENERIC_ALL
	);

	// Anonymous directory object visible to the target. KnownDlls resolution
	// gets redirected into it for the duration of the injection.
	this->AnonymousDirectoryHandle = CreateAnonymousDirectoryObject(
		this->TokenAccessibleSecurityDescriptor
	);

	this->LocalKnownDllsHandle = OpenDirectoryObject(L"\\KnownDlls", DIRECTORY_QUERY | DIRECTORY_TRAVERSE);
	this->RemoteKnownDllsHandle = FindRemoteKnownDllsHandle();

	DebugLog(L"AnonymousDirectoryHandle: %p", this->AnonymousDirectoryHandle);
	DebugLog(L"LocalKnownDllsHandle: %p", this->LocalKnownDllsHandle);
	DebugLog(L"RemoteKnownDllsHandle: %p", this->RemoteKnownDllsHandle);
}

SimpleInjector::~SimpleInjector()
{
	if (this->LocalModuleHandle) {
		FreeLibrary(this->LocalModuleHandle);
	}

	CloseHandle(this->LocalKnownDllsHandle);
	CloseHandle(this->AnonymousDirectoryHandle);
	CloseHandle(this->ProcessTokenHandle);
	CloseHandle(this->ProcessHandle);
	LocalFree(this->TokenAccessibleSecurityDescriptor);
}

//
// memory operations
//

LPVOID
SimpleInjector::AllocateProcessMemory(
	DWORD Size,
	DWORD AllocationType,
	DWORD PageProtection
)
{
	LPVOID RemoteBuffer = ::VirtualAllocEx(this->ProcessHandle, NULL, Size, AllocationType, PageProtection);

	if (!RemoteBuffer) {
		ErrorLog(L"VirtualAllocEx failed.");
	}

	return RemoteBuffer;
}

BOOLEAN
SimpleInjector::FreeProcessMemory(
	LPVOID RemoteBuffer,
	DWORD Size,
	DWORD FreeType
)
{
	BOOLEAN Success = ::VirtualFreeEx(this->ProcessHandle, RemoteBuffer, Size, FreeType);

	if (!Success) {
		ErrorLog(L"VirtualFreeEx failed.");
	}

	return Success;
}

SIZE_T
SimpleInjector::ReadProcessMemory(
	LPVOID Destination,
	LPVOID Source,
	DWORD Size
)
{
	SIZE_T BytesTransferred = 0;

	if (!::ReadProcessMemory(this->ProcessHandle, Source, Destination, Size, &BytesTransferred)) {
		ErrorLog(L"ReadProcessMemory failed.");
	}

	return BytesTransferred;
}

SIZE_T
SimpleInjector::WriteProcessMemory(
	LPVOID Destination,
	LPVOID Source,
	DWORD Size
)
{
	SIZE_T BytesTransferred = 0;

	if (!::WriteProcessMemory(this->ProcessHandle, Destination, Source, Size, &BytesTransferred)) {
		ErrorLog(L"WriteProcessMemory failed.");
	}

	return BytesTransferred;
}

DWORD
SimpleInjector::ProtectProcessMemory(
	LPVOID Address,
	SIZE_T Size,
	DWORD NewProtect
)
{
	DWORD OldProtect = 0;

	if (!VirtualProtectEx(this->ProcessHandle, Address, Size, NewProtect, &OldProtect)) {
		ErrorLog(L"VirtualProtectEx failed.");
	}

	return OldProtect;
}

//
// handle operations
//

HANDLE
SimpleInjector::DuplicateHandleToProcess(
	HANDLE LocalHandle
)
{
	HANDLE RemoteHandle = NULL;

	if (!::DuplicateHandle(GetCurrentProcess(), LocalHandle, this->ProcessHandle,
		&RemoteHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
		ErrorLog(L"Failed to duplicate handle %p into target process.", LocalHandle);
	}

	return RemoteHandle;
}

HANDLE
SimpleInjector::DuplicateHandleFromProcess(
	HANDLE RemoteHandle
)
{
	HANDLE LocalHandle = NULL;

	// Failures are expected here -- this is used to probe arbitrary
	// handle values in the target process.
	::DuplicateHandle(this->ProcessHandle, RemoteHandle, GetCurrentProcess(),
		&LocalHandle, 0, FALSE, DUPLICATE_SAME_ACCESS);

	return LocalHandle;
}

BOOLEAN
SimpleInjector::CloseProcessHandle(
	HANDLE RemoteHandle
)
{
	// Closes a handle inside the target process.
	BOOLEAN Success = ::DuplicateHandle(this->ProcessHandle, RemoteHandle, NULL,
		NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);

	if (!Success) {
		ErrorLog(L"Failed to close remote handle %p.", RemoteHandle);
	}

	return Success;
}

//
// KnownDlls handle hijacking
//

HANDLE
SimpleInjector::FindRemoteKnownDllsHandle()
{
	// Handle values in a fresh process are small and 4-aligned; probe each one
	// and compare the underlying object against our local \KnownDlls handle.
	for (ULONG_PTR RemoteHandleValue = 4; RemoteHandleValue < 0x1000; RemoteHandleValue += 4) {

		HANDLE RemoteHandle = (HANDLE)RemoteHandleValue;
		HANDLE LocalHandle = DuplicateHandleFromProcess(RemoteHandle);

		if (!LocalHandle) {
			continue;
		}

		BOOLEAN SameObject = NT_SUCCESS(NtCompareObjects(LocalHandle, this->LocalKnownDllsHandle));
		CloseHandle(LocalHandle);

		if (SameObject) {
			Log(L"Found remote KnownDlls handle -- %p", RemoteHandle);
			return RemoteHandle;
		}
	}

	ErrorLog(L"Failed to find remote KnownDlls handle.");
	return NULL;
}

BOOLEAN
SimpleInjector::SwapRemoteKnownDllsHandle(
	HANDLE NewHandle,
	LPCWSTR Action
)
{
	// Free the KnownDlls handle slot in the target, then repeatedly duplicate
	// the replacement handle until it lands on the freed slot value.
	CloseProcessHandle(this->RemoteKnownDllsHandle);

	for (INT i = 0; i < 0x1000; i++) {

		HANDLE CurrentRemoteHandle = DuplicateHandleToProcess(NewHandle);

		if (CurrentRemoteHandle == this->RemoteKnownDllsHandle) {
			Log(L"%s remote KnownDlls handle...", Action);
			return TRUE;
		}

		CloseProcessHandle(CurrentRemoteHandle);
	}

	ErrorLog(L"Failed to swap remote KnownDlls handle (%s).", Action);
	return FALSE;
}

//
// anonymous directory population
//

HANDLE
SimpleInjector::CreateAnonymousDirectoryObject(
	PSECURITY_DESCRIPTOR SecurityDescriptor
)
{
	UNICODE_STRING ObjectName = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	HANDLE DirectoryHandle = NULL;

	RtlInitUnicodeString(&ObjectName, NULL);
	InitializeObjectAttributes(&ObjectAttributes, &ObjectName, OBJ_CASE_INSENSITIVE, NULL, SecurityDescriptor);

	NTSTATUS Status = NtCreateDirectoryObject(&DirectoryHandle, DIRECTORY_ALL_ACCESS, &ObjectAttributes);

	if (!NT_SUCCESS(Status)) {
		ErrorLog(L"NtCreateDirectoryObject failed with status 0x%x.", Status);
	}

	return DirectoryHandle;
}

HANDLE
SimpleInjector::CreateSectionImageFromFile(
	LPCWSTR SectionName,
	LPCWSTR FullImageName
)
{
	HANDLE FileHandle = CreateFileW(
		FullImageName, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
	);

	if (FileHandle == INVALID_HANDLE_VALUE) {
		Log(L"Error 0x%x -- Failed to open file %s.", GetLastError(), FullImageName);
		return NULL;
	}

	// Create a named SEC_IMAGE section inside the anonymous directory.
	UNICODE_STRING SectionNameUnicode;
	OBJECT_ATTRIBUTES ObjectAttributes;

	RtlInitUnicodeString(&SectionNameUnicode, SectionName);
	InitializeObjectAttributes(
		&ObjectAttributes, &SectionNameUnicode, OBJ_CASE_INSENSITIVE,
		this->AnonymousDirectoryHandle, this->TokenAccessibleSecurityDescriptor
	);

	HANDLE SectionHandle = NULL;
	NTSTATUS Status = NtCreateSection(
		&SectionHandle, MAXIMUM_ALLOWED, &ObjectAttributes, NULL,
		PAGE_READONLY, SEC_IMAGE, FileHandle
	);

	CloseHandle(FileHandle);

	if (!NT_SUCCESS(Status)) {
		Log(L"Error 0x%x -- Failed to create section %s.", Status, SectionName);
		return NULL;
	}

	return SectionHandle;
}

VOID
SimpleInjector::AddDependenciesToAnonymousDirectory(
	LPCWSTR LibraryName
)
{
	WCHAR FullImageName[MAX_PATH];
	LPWSTR FilePart = NULL;

	if (!GetFullPathNameW(LibraryName, MAX_PATH, FullImageName, &FilePart)) {
		ErrorLog(L"GetFullPathName failed for %s.", LibraryName);
	}

	// Load the library locally so its full dependency graph appears in our module list.
	this->LocalModuleHandle = LoadLibraryW(FullImageName);

	// Create a named image section for every module in this process inside the
	// anonymous directory, so the loader of the target process can resolve
	// them all from there.
	DWORD BytesNeeded = 0;

	if (!EnumProcessModulesEx(GetCurrentProcess(), NULL, 0, &BytesNeeded, LIST_MODULES_ALL)) {
		ErrorLog(L"EnumProcessModulesEx failed.");
	}

	HMODULE* ModuleArray = (HMODULE*)LocalAlloc(LPTR, BytesNeeded);
	if (!ModuleArray) {
		ErrorLog(L"Out of memory allocating module array.");
	}

	if (EnumProcessModulesEx(GetCurrentProcess(), ModuleArray, BytesNeeded, &BytesNeeded, LIST_MODULES_ALL)) {

		for (DWORD i = 0; i < BytesNeeded / sizeof(HMODULE); i++) {

			WCHAR ModulePath[MAX_PATH];

			if (!GetModuleFileNameExW(GetCurrentProcess(), ModuleArray[i], ModulePath, MAX_PATH)) {
				continue;
			}

			GetFullPathNameW(ModulePath, MAX_PATH, FullImageName, &FilePart);

			// The section handle is intentionally left open -- the named
			// section must stay alive in the directory for the loader of
			// the target process to resolve it.
			HANDLE SectionHandle = CreateSectionImageFromFile(FilePart, FullImageName);

			DebugLog(L"Adding dependency: %s -- %s -- %p", FullImageName, FilePart, SectionHandle);
		}
	}

	LocalFree(ModuleArray);
}

//
// module operations
//

HMODULE
SimpleInjector::RemoteGetModuleHandle(
	LPCWSTR RemoteModuleName
)
{
	HMODULE ModuleHandle = NULL;
	DWORD BytesNeeded = 0;

	if (!EnumProcessModulesEx(this->ProcessHandle, NULL, 0, &BytesNeeded, LIST_MODULES_ALL)) {
		ErrorLog(L"EnumProcessModulesEx failed.");
	}

	HMODULE* ModuleArray = (HMODULE*)LocalAlloc(LPTR, BytesNeeded);
	if (!ModuleArray) {
		ErrorLog(L"Out of memory allocating module array.");
	}

	if (EnumProcessModulesEx(this->ProcessHandle, ModuleArray, BytesNeeded, &BytesNeeded, LIST_MODULES_ALL)) {

		WCHAR ModulePath[MAX_PATH];

		for (DWORD i = 0; i < BytesNeeded / sizeof(HMODULE); i++) {

			if (!GetModuleFileNameExW(this->ProcessHandle, ModuleArray[i], ModulePath, MAX_PATH)) {
				continue;
			}

			DebugLog(L"Module to match: %s -- Current module: %s", RemoteModuleName, ModulePath);

			if (wcsstr(ModulePath, RemoteModuleName)) {
				ModuleHandle = ModuleArray[i];
				DebugLog(L"MODULE MATCH FOUND -- Name: %s | Base: %p", RemoteModuleName, ModuleHandle);
				break;
			}
		}
	}

	LocalFree(ModuleArray);
	return ModuleHandle;
}

HMODULE
SimpleInjector::RemoteLoadLibrary(
	LPCWSTR LibraryName
)
{
	//
	// Loads a 64 bit module from a native 64 bit process into a native 64 bit process.
	//

	WCHAR FullImageName[MAX_PATH];
	LPWSTR FilePart = NULL;

	if (!GetFullPathNameW(LibraryName, MAX_PATH, FullImageName, &FilePart)) {
		ErrorLog(L"GetFullPathName failed for %s.", LibraryName);
	}

	// Populate the anonymous directory with named sections for the library and
	// its dependencies, then redirect KnownDlls resolution in the target into it.
	AddDependenciesToAnonymousDirectory(LibraryName);
	SwapRemoteKnownDllsHandle(this->AnonymousDirectoryHandle, L"Replacing");

	Log(L"Loading DLL into target process...");

	// Copy the library file name into the target as the LoadLibraryW argument.
	DWORD NameLengthBytes = ((DWORD)wcslen(FilePart) + 1) * sizeof(WCHAR);

	LPVOID RemoteSectionNameString = AllocateProcessMemory(
		NameLengthBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
	);

	WriteProcessMemory(RemoteSectionNameString, FilePart, NameLengthBytes);

	// LoadLibraryW sits at the same address in the target process, so it can
	// be used directly as the thread start address.
	HANDLE ThreadHandle = ::CreateRemoteThread(
		this->ProcessHandle, NULL, 0,
		(LPTHREAD_START_ROUTINE)LoadLibraryW,
		RemoteSectionNameString, CREATE_SUSPENDED, NULL
	);

	if (!ThreadHandle) {
		ErrorLog(L"CreateRemoteThread for LoadLibraryW failed.");
	}

	::ResumeThread(ThreadHandle);
	::WaitForSingleObject(ThreadHandle, INFINITE);

	DWORD RemoteThreadExitCode = 0;
	::GetExitCodeThread(ThreadHandle, &RemoteThreadExitCode);
	::CloseHandle(ThreadHandle);

	DebugLog(L"LoadLibraryW remote thread exit code: %d", RemoteThreadExitCode);

	// Restore the original KnownDlls handle and clean up the argument buffer.
	FreeProcessMemory(RemoteSectionNameString, 0, MEM_RELEASE);
	SwapRemoteKnownDllsHandle(this->LocalKnownDllsHandle, L"Restoring");

	return RemoteGetModuleHandle(FilePart);
}

VOID
SimpleInjector::RemoteFreeLibrary(
	HMODULE RemoteModuleHandle
)
{
	HANDLE ThreadHandle = ::CreateRemoteThread(
		this->ProcessHandle, NULL, 0,
		(LPTHREAD_START_ROUTINE)FreeLibrary,
		RemoteModuleHandle, CREATE_SUSPENDED, NULL
	);

	if (!ThreadHandle) {
		ErrorLog(L"CreateRemoteThread for FreeLibrary failed.");
	}

	::ResumeThread(ThreadHandle);
	::WaitForSingleObject(ThreadHandle, INFINITE);
	::CloseHandle(ThreadHandle);
}

LPVOID
SimpleInjector::RemoteGetProcAddress(
	HMODULE RemoteLibraryModule,
	LPCWSTR RemoteProcName
)
{
	// The library was already loaded locally by AddDependenciesToAnonymousDirectory.
	// Resolve the export locally, then apply its offset to the remote module base.
	if (!this->LocalModuleHandle) {
		Log(L"No locally loaded module available to resolve exported symbol %s.", RemoteProcName);
		return NULL;
	}

	CHAR FunctionName[MAX_PATH] = { 0 };
	size_t NumChars = 0;
	wcstombs_s(&NumChars, FunctionName, RemoteProcName, MAX_PATH);

	FARPROC LocalAddress = GetProcAddress(this->LocalModuleHandle, FunctionName);

	if (!LocalAddress) {
		Log(L"Could not resolve exported symbol %s.", RemoteProcName);
		return NULL;
	}

	// Remote address = remote module base + export offset within the local copy.
	return (LPVOID)((UINT_PTR)RemoteLibraryModule + ((UINT_PTR)LocalAddress - (UINT_PTR)this->LocalModuleHandle));
}

//
// thread operations
//

HANDLE
SimpleInjector::RemoteCreateThreadSimple(
	LPVOID Address,
	LPVOID Argument
)
{
	HANDLE ThreadHandle = ::CreateRemoteThread(
		this->ProcessHandle, NULL, 0,
		(LPTHREAD_START_ROUTINE)Address, Argument,
		CREATE_SUSPENDED, NULL
	);

	if (!ThreadHandle) {
		ErrorLog(L"CreateRemoteThread failed.");
	}

	::ResumeThread(ThreadHandle);

	return ThreadHandle;
}

ULONG
SimpleInjector::RemoteCreateThreadSimpleSyncWithLogging(
	LPVOID Address
)
{
	PIPE_PAIR PipePair = { 0 };

	if (!CreateNamedPipeChannel(&PipePair)) {
		ErrorLog(L"Failed to create logging pipe.");
	}

	// The remote thread receives the client end of the pipe as its argument,
	// wrapped in a PIPE_AND_ARGUMENT structure in the target.
	HANDLE RemoteClientPipe = DuplicateHandleToProcess(PipePair.Client);

	PIPE_AND_ARGUMENT PnA = { 0 };
	PnA.Pipe = RemoteClientPipe;
	PnA.Argument = NULL;

	LPVOID RemoteArgument = AllocateProcessMemory(
		sizeof(PIPE_AND_ARGUMENT), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
	);

	WriteProcessMemory(RemoteArgument, &PnA, sizeof(PIPE_AND_ARGUMENT));

	HANDLE ThreadHandle = RemoteCreateThreadSimple(Address, RemoteArgument);

	printf("\n--- Remote Thread Log ---\n");

	// Pump the pipe until the remote thread exits and the pipe is drained.
	DWORD BytesRead = 0, TotalAvailable = 0, MessageAvailable = 0;
	DWORD RemoteThreadExitCode = STILL_ACTIVE;

	while (RemoteThreadExitCode == STILL_ACTIVE || TotalAvailable) {

		if (!PeekNamedPipe(PipePair.Server, NULL, 0, NULL, &TotalAvailable, &MessageAvailable)) {
			break;
		}

		if (MessageAvailable) {

			PBYTE Output = (PBYTE)LocalAlloc(LPTR, MessageAvailable + 1);
			if (!Output) {
				ErrorLog(L"Out of memory.");
			}

			if (ReadFile(PipePair.Server, Output, MessageAvailable, &BytesRead, NULL)) {
				printf("<[%d]> %s", this->Pid, Output);
			}

			LocalFree(Output);
			TotalAvailable -= BytesRead;
		}
		else {
			Sleep(50); // Idle while the remote thread runs -- do not busy wait.
		}

		::GetExitCodeThread(ThreadHandle, &RemoteThreadExitCode);
	}

	printf("\n--- Remote Thread Log ---\n\n");

	Log(L"Thread exited with (decimal) code: %d", RemoteThreadExitCode);

	CloseProcessHandle(RemoteClientPipe);
	::CloseHandle(ThreadHandle);
	::CloseHandle(PipePair.Client);
	::CloseHandle(PipePair.Server);

	return RemoteThreadExitCode;
}

//
// entry point
//

int wmain(int argc, wchar_t* argv[])
{
	if (argc != 4) {
		Log(L"Usage: %s <pid> <dll> <func>", argv[0]);
		return 1;
	}

	DWORD ProcessIdentifier = _wtoi(argv[1]);
	LPCWSTR LibraryName = argv[2];
	LPCWSTR FunctionName = argv[3];

	// Initialize the injector with the PID of the target process.
	SimpleInjector* Injector = new SimpleInjector(ProcessIdentifier);

	// Load the library into the sandboxed process. The returned handle is the
	// base address of the library in the target process.
	HMODULE RemoteModule = Injector->RemoteLoadLibrary(LibraryName);

	if (!RemoteModule) {
		Log(L"Failed to load library into remote process!");
		return 1;
	}

	Log(L"Library \"%s\" has been loaded at base %p in target process.", LibraryName, RemoteModule);

	// Resolve the remote address of the exported function in the remote dll.
	LPVOID RemoteFunction = Injector->RemoteGetProcAddress(RemoteModule, FunctionName);

	if (!RemoteFunction) {
		Log(L"Freeing remote module.");
		Injector->RemoteFreeLibrary(RemoteModule);
		return 1;
	}

	Log(L"Exported function \"%s\" is located at address %p in target process.", FunctionName, RemoteFunction);

	// Call the function, automatically providing a handle to the client end of
	// a pipe as the argument, and print everything it logs until it exits.
	// Use RemoteCreateThreadSimple instead to run it without the logging pipe.
	Injector->RemoteCreateThreadSimpleSyncWithLogging(RemoteFunction);

	// The remote thread has completed, so it is now safe to unload the library.
	Log(L"Freeing remote module.");
	Injector->RemoteFreeLibrary(RemoteModule);

	delete Injector;

	return 0;
}

