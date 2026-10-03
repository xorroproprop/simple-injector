# windows-simple-injector

A small Windows DLL injector that can load a library into a sandboxed process
(AppContainer / Less Privileged AppContainer), where the usual
`VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread(LoadLibrary)`
approach fails because the target cannot open the DLL file or its
`\KnownDlls` sections.

## How it works

1. Builds a security descriptor from the target process token that grants
   every enabled group, restricted SID, AppContainer SID and matching
   integrity label access to the objects it creates.
2. Creates an **anonymous NT directory object** protected by that descriptor
   and populates it with named `SEC_IMAGE` sections for the DLL and every
   module loaded in the injector process (the dependency closure).
3. Finds the target's `\KnownDlls` directory handle by probing its handle
   table with `NtCompareObjects`.
4. Closes the remote `\KnownDlls` handle and recycles its handle-table slot
   with a duplicate of the anonymous directory handle, so the loader in the
   target resolves DLL names from the anonymous directory.
5. Calls `LoadLibraryW` in the target via `CreateRemoteThread`, waits for
   `DLL_PROCESS_ATTACH` to finish, then restores the original handle.

Optionally resolves an export in the remote module (`RemoteGetProcAddress`)
and runs it with a handle to the client end of a message pipe as its only
argument. Everything the DLL writes to that pipe is streamed back to the
injector console. `ExampleDLL` demonstrates this pattern.

## Usage

```text
SimpleInjector.exe <pid> <dll> <exported function>
```

Example:

```text
SimpleInjector.exe 4242 C:\path\to\ExampleDLL.dll Example
```

## Building

* Visual Studio 2022 (toolset v143) with the Windows SDK
* Open `SimpleInjector.sln` and build the `x64` configuration
* `ExampleDLL` builds the sample DLL used for testing
* Only external dependency: `ntdll.lib` (already referenced by the projects)

Run from an elevated prompt; opening the target process requires
`PROCESS_CREATE_THREAD | PROCESS_VM_* | PROCESS_DUP_HANDLE` access.

## Project layout

| Path | Description |
| ---- | ----------- |
| `SimpleInjector/` | Injector executable (`SimpleInjector` class + helpers) |
| `ExampleDLL/` | Sample DLL with an exported `Example` function that logs over the pipe |

## Notes

* 64-bit only: the injector, the target process and the DLL must all match.
* `ErrorLog` terminates the process on failure, so errors are loud by design.

## Disclaimer

This project is published for educational and research purposes only. Only
use it on systems you own or are explicitly authorized to test.
