#pragma once
/*
*
Non-Official Maintained NtAlpc Header File C++

*/

#pragma once
#pragma comment(lib, "ntdll")
#pragma comment(lib, "kernel32")

#include <Windows.h> 
#include <winternl.h>

/*
Windows 10+
Disclaimer: We can support previous verious i.e., Windows 8. Its just not in our current use-case scenario.
*/
#define WINVER 0x0A00 
#define MAX_LEN 0x500 
#pragma warning (push, 0)
#pragma warning(disable : 4005)
#pragma warning(pop)

#define ALPC_PORTFLG_NONE 0x0
#define ALPC_PORTFLG_LPCPORT 0x1000 // Only usable in kernel
#define ALPC_PORTFLG_ALLOWIMPERSONATION 0x10000 // Can be set by client to allow server to impersonation this client
#define ALPC_PORTFLG_ALLOW_LPC_REQUESTS 0x20000
#define ALPC_PORTFLG_WAITABLE_PORT 0x40000	// Allow port to be used with synchronization mechanisms like Semaphores
#define ALPC_PORTFLG_SYSTEM_PROCESS 0x100000 // Only usable in kernel
#define ALPC_PORTFLG_ALLOW_DUP_OBJECT 0x80000
#define ALPC_PORTFLG_LRPC_WAKE_POLICY1 0x200000
#define ALPC_PORTFLG_LRPC_WAKE_POLICY2 0x400000
#define ALPC_PORTFLG_LRPC_WAKE_POLICY3 0x800000

// ALPC Message Flags
#define ALPC_MSGFLG_NONE 0x0
#define ALPC_MSGFLG_REPLY_MESSAGE 0x1
#define ALPC_MSGFLG_LPC_MODE 0x2
#define ALPC_MSGFLG_RELEASE_MESSAGE 0x10000
#define ALPC_MSGFLG_SYNC_REQUEST 0x20000		// synchronous message, needs a receive buffer or else error 0xC0000705 is returned
#define ALPC_MSGFLG_WAIT_USER_MODE 0x100000
#define ALPC_MSGFLG_WAIT_ALERTABLE 0x200000
#define ALPC_MSGFLG_WOW64_CALL 0x80000000

#define ALPC_MESSAGE_SECURITY_ATTRIBUTE 0x80000000
#define ALPC_MESSAGE_VIEW_ATTRIBUTE 0x40000000
#define ALPC_MESSAGE_CONTEXT_ATTRIBUTE 0x20000000
#define ALPC_MESSAGE_HANDLE_ATTRIBUTE 0x10000000
#define ALPC_MESSAGE_TOKEN_ATTRIBUTE 0x8000000
#define ALPC_MESSAGE_DIRECT_ATTRIBUTE 0x4000000
#define ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE 0x2000000	


#define ALPC_SYNC_CONNECTION 0x20000 // Synchronous connection request
#define ALPC_USER_WAIT_MODE 0x100000 // Wait in user mode
#define ALPC_WAIT_IS_ALERTABLE 0x200000 // Wait in alertable mode

#define ALPC_MESSAGE_ATTRIBUTE_ALL ALPC_MESSAGE_SECURITY_ATTRIBUTE | ALPC_MESSAGE_VIEW_ATTRIBUTE | ALPC_MESSAGE_CONTEXT_ATTRIBUTE | ALPC_MESSAGE_HANDLE_ATTRIBUTE | ALPC_MESSAGE_TOKEN_ATTRIBUTE | ALPC_MESSAGE_DIRECT_ATTRIBUTE | ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE

/*
*
NtAlpc Structures

*/

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
	ULONG AllocatedAttributes;
	ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

typedef struct _ALPC_PORT_ATTRIBUTES
{
	ULONG Flags;
	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	SIZE_T MaxMessageLength;
	SIZE_T MemoryBandwidth;
	SIZE_T MaxPoolUsage;
	SIZE_T MaxSectionSize;
	SIZE_T MaxViewSize;
	SIZE_T MaxTotalSectionSize;
	ULONG DupObjectTypes;
#ifdef _WIN64
	ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, * PALPC_PORT_ATTRIBUTES;

typedef struct _PORT_MESSAGE
{
	union
	{
		struct
		{
			SHORT DataLength;
			SHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union
	{
		struct
		{
			SHORT Type;
			SHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double DoNotUseThisField;
	};
	ULONG MessageId;
	union
	{
		SIZE_T ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
		ULONG CallbackId; // only valid for LPC_REQUEST messages
	};
} PORT_MESSAGE, * PPORT_MESSAGE;

typedef struct _ALPC_DATA_VIEW_ATTR {
	ULONG Flags;
	HANDLE SectionHandle;
	PVOID ViewBase;
	SIZE_T ViewSize;
} ALPC_DATA_VIEW_ATTR, * PALPC_DATA_VIEW_ATTR;

typedef struct _ALPC_TOKEN_ATTR
{
	ULONGLONG TokenId;
	ULONGLONG AuthenticationId;
	ULONGLONG ModifiedId;
} ALPC_TOKEN_ATTR, * PALPC_TOKEN_ATTR;

typedef struct _AlpcPortContext {
	HANDLE Handle;
} AlpcPortContext, * PAlpcPortContext;

typedef struct _ALPC_CONTEXT_ATTR {
	PVOID PortContext;
	PVOID MessageContext;
	ULONG Sequence;
	ULONG MessageId;
	ULONG CallbackId;
} ALPC_CONTEXT_ATTR, * PALPC_CONTEXT_ATTR;

typedef struct _ALPC_SECURITY_ATTR {
	ULONG Flags;
	PSECURITY_QUALITY_OF_SERVICE pQOS;
	HANDLE ContextHandle;
} ALPC_SECURITY_ATTR, * PALPC_SECURITY_ATTR;


typedef struct _SECURITY_CLIENT_CONTEXT
{
	SECURITY_QUALITY_OF_SERVICE SecurityQos;	//_KALPC_SECURITY_DATA
	LPVOID ClientToken;
	UCHAR DirectlyAccessClientToken;
	UCHAR DirectAccessEffectiveOnly;
	UCHAR ServerIsRemote;
	_TOKEN_CONTROL ClientTokenControl;
} SECURITY_CLIENT_CONTEXT, * PSECURITY_CLIENT_CONTEXT;

typedef struct _ALPC_DIRECT_ATTR
{
	HANDLE Event;
} ALPC_DIRECT_ATTR, * PALPC_DIRECT_ATTR;

typedef struct _ALPC_WORK_ON_BEHALF_ATTR
{
	ULONGLONG Ticket;
} ALPC_WORK_ON_BEHALF_ATTR, * PALPC_WORK_ON_BEHALF_ATTR;

typedef struct _ALPC_HANDLE_ATTR
{
	ULONG Flags;
	HANDLE Handle;
	ULONG ObjectType;
	ACCESS_MASK DesiredAccess;
} ALPC_HANDLE_ATTR, * PALPC_HANDLE_ATTR;

typedef struct _PORT_VIEW
{
	ULONG Length;
	HANDLE SectionHandle;
	ULONG SectionOffset;
	SIZE_T ViewSize;
	PVOID ViewBase;
	PVOID ViewRemoteBase;
} PORT_VIEW, * PPORT_VIEW;

/*
Define undocumented NtFunctions

*/

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAlpcConnectPortEx(
	_Out_ PHANDLE PortHandle,
	_In_ POBJECT_ATTRIBUTES ConnectionPortObjectAttributes,
	_In_opt_ POBJECT_ATTRIBUTES ClientPortObjectAttributes,
	_In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
	_In_ ULONG Flags,
	_In_opt_ PSECURITY_DESCRIPTOR ServerSecurityRequirements,
	_Inout_updates_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ConnectionMessage,
	_Inout_opt_ PSIZE_T BufferLength,
	_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
	_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
	_In_opt_ PLARGE_INTEGER Timeout
);


NTSYSCALLAPI
NTSTATUS
NTAPI
NtAlpcConnectPort(
	_Out_ PHANDLE PortHandle,
	_In_ PUNICODE_STRING PortName,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
	_In_ DWORD ConnectionFlags,
	_In_opt_ PSID RequiredServerSid,
	_In_opt_ PPORT_MESSAGE ConnectionMessage,
	_Inout_opt_ PSIZE_T ConnectMessageSize,
	_In_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
	_In_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
	_In_opt_ PLARGE_INTEGER Timeout
);


NTSTATUS
NTAPI
AlpcInitializeMessageAttribute(
	_In_ ULONG AttributeFlags,
	_Out_opt_ PALPC_MESSAGE_ATTRIBUTES Buffer,
	_In_ SIZE_T BufferSize,
	_Out_ PSIZE_T RequiredBufferSize
);


NTSYSCALLAPI
NTSTATUS
NTAPI
NtAlpcCreatePortSection(
	_In_ HANDLE PortHandle,
	_In_ ULONG Flags,
	_In_opt_ HANDLE SectionHandle,
	_In_ SIZE_T SectionSize,
	_Out_ PHANDLE AlpcSectionHandle,
	_Out_ PSIZE_T ActualSectionSize
);


NTSYSCALLAPI
NTSTATUS
NTAPI
NtAlpcCreateSectionView(
	_In_ HANDLE 	PortHandle,
	_Reserved_ ULONG 	Flags,
	_Inout_ PALPC_DATA_VIEW_ATTR 	ViewAttributes
);


NTSYSCALLAPI
NTSTATUS
NTAPI
NtAlpcCreatePort(
	_Out_ PHANDLE PortHandle,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes
);


NTSYSCALLAPI
NTSTATUS
NTAPI
NtAlpcSendWaitReceivePort(
	_In_ HANDLE PortHandle,
	_In_ ULONG Flags,
	_In_reads_bytes_opt_(SendMessage->u1.s1.TotalLength) PPORT_MESSAGE SendMessage,
	_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
	_Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ReceiveMessage,
	_Inout_opt_ PSIZE_T BufferLength,
	_Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
	_In_opt_ PLARGE_INTEGER Timeout
);


NTSYSCALLAPI
NTSTATUS
NTAPI
NtAlpcDeleteSectionView(
	_In_ HANDLE PortHandle,
	_Reserved_ ULONG Flags,
	_In_ PVOID ViewBase
);


NTSYSCALLAPI
NTSTATUS
NTAPI
AlpcGetHeaderSize(
	ULONG TypeFlag
);


BOOL ConvertStringSecurityDescriptorToSecurityDescriptorA(
	LPCSTR               StringSecurityDescriptor,
	DWORD                StringSDRevision,
	PSECURITY_DESCRIPTOR * SecurityDescriptor,
	PULONG               SecurityDescriptorSize
);
