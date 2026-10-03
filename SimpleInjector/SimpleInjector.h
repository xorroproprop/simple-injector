#pragma once

#include <Windows.h>

//
// Loads a library into a sandboxed (AppContainer / LPAC) process by swapping
// the target's \KnownDlls directory handle with an anonymous directory that
// contains named SEC_IMAGE sections for the library and its dependencies.
//

class SimpleInjector {
	public:

		SimpleInjector(DWORD Pid);
		~SimpleInjector();

		//
		// memory operations
		//

		LPVOID AllocateProcessMemory(DWORD Size, DWORD AllocationType, DWORD PageProtection);
		BOOLEAN FreeProcessMemory(LPVOID RemoteBuffer, DWORD Size, DWORD FreeType);
		SIZE_T ReadProcessMemory(LPVOID Destination, LPVOID Source, DWORD Size);
		SIZE_T WriteProcessMemory(LPVOID Destination, LPVOID Source, DWORD Size);
		DWORD ProtectProcessMemory(LPVOID Address, SIZE_T Size, DWORD NewProtect);

		//
		// handle operations
		//

		HANDLE DuplicateHandleToProcess(HANDLE LocalHandle);
		HANDLE DuplicateHandleFromProcess(HANDLE RemoteHandle);
		BOOLEAN CloseProcessHandle(HANDLE RemoteHandle);

		//
		// module operations
		//

		HMODULE RemoteLoadLibrary(LPCWSTR LibraryName);
		VOID RemoteFreeLibrary(HMODULE RemoteModuleHandle);
		HMODULE RemoteGetModuleHandle(LPCWSTR RemoteModuleName);
		LPVOID RemoteGetProcAddress(HMODULE RemoteLibraryModule, LPCWSTR RemoteProcName);
		VOID AddDependenciesToAnonymousDirectory(LPCWSTR LibraryName);

		//
		// thread operations
		//

		HANDLE RemoteCreateThreadSimple(LPVOID Address, LPVOID Argument);
		ULONG RemoteCreateThreadSimpleSyncWithLogging(LPVOID Address);

	private:

		DWORD Pid;
		HANDLE ProcessHandle, ProcessTokenHandle;
		HANDLE LocalKnownDllsHandle, RemoteKnownDllsHandle;
		HANDLE AnonymousDirectoryHandle;
		HMODULE LocalModuleHandle;
		PSECURITY_DESCRIPTOR TokenAccessibleSecurityDescriptor;

		HANDLE FindRemoteKnownDllsHandle();
		BOOLEAN SwapRemoteKnownDllsHandle(HANDLE NewHandle, LPCWSTR Action);
		HANDLE CreateAnonymousDirectoryObject(PSECURITY_DESCRIPTOR SecurityDescriptor);
		HANDLE CreateSectionImageFromFile(LPCWSTR SectionName, LPCWSTR FullImageName);
};
