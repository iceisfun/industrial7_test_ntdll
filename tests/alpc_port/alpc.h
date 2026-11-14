/* Shared ALPC declarations for the alpc_* areas (the SDK headers do not carry them). */
#ifndef ALPC_H
#define ALPC_H
#include "t.h"

typedef ULONG_PTR ALPC_HANDLE_T;

typedef struct { ULONG Length; SECURITY_IMPERSONATION_LEVEL ImpersonationLevel; BYTE ContextTrackingMode; BYTE EffectiveOnly; } A_QOS;

typedef struct {
    ULONG Flags;
    A_QOS SecurityQos;
    SIZE_T MaxMessageLength;
    SIZE_T MemoryBandwidth;
    SIZE_T MaxPoolUsage;
    SIZE_T MaxSectionSize;
    SIZE_T MaxViewSize;
    SIZE_T MaxTotalSectionSize;
    ULONG DupObjectTypes;
    ULONG Reserved;
} A_PORT_ATTR;

typedef struct {
    USHORT DataLength;
    USHORT TotalLength;
    SHORT Type;
    SHORT DataInfoOffset;
    CLIENT_ID ClientId;
    ULONG MessageId;
    ULONG_PTR ClientViewSize;     /* also CallbackId */
} A_MSG;

typedef struct { ULONG AllocatedAttributes; ULONG ValidAttributes; } A_MSG_ATTR;

typedef struct { ULONG Flags; A_QOS *SecurityQos; ALPC_HANDLE_T ContextHandle; ULONG Reserved1, Reserved2; } A_SEC_ATTR;
typedef struct { ULONG Flags; HANDLE SectionHandle; PVOID ViewBase; SIZE_T ViewSize; } A_VIEW_ATTR;
typedef struct { PVOID PortContext; PVOID MessageContext; ULONG Sequence; ULONG MessageId; ULONG CallbackId; } A_CTX_ATTR;

typedef struct { ULONG Flags; ULONG SequenceNo; PVOID PortContext; } A_BASIC_INFO;

#define A_ATTR_SECURITY 0x80000000u
#define A_ATTR_VIEW     0x40000000u
#define A_ATTR_CONTEXT  0x20000000u
#define A_ATTR_HANDLE   0x10000000u
#define A_ATTR_TOKEN    0x08000000u
#define A_ATTR_DIRECT   0x04000000u

#define ALPC_MSG_TYPE(m) ((m)->Type & 0xff)
#define LPC_REQUEST 1
#define LPC_REPLY 2
#define LPC_DATAGRAM 3
#define LPC_LOST_REPLY 4
#define LPC_PORT_CLOSED 5
#define LPC_CLIENT_DIED 6
#define LPC_CONNECTION_REQUEST 10

UDECL(NTSTATUS, NtAlpcCreatePort, (PHANDLE, POBJECT_ATTRIBUTES, A_PORT_ATTR *));
UDECL(NTSTATUS, NtAlpcConnectPort, (PHANDLE, PUNICODE_STRING, POBJECT_ATTRIBUTES, A_PORT_ATTR *, ULONG, PSID, A_MSG *, PULONG, A_MSG_ATTR *, A_MSG_ATTR *, PLARGE_INTEGER));
UDECL(NTSTATUS, NtAlpcConnectPortEx, (PHANDLE, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, A_PORT_ATTR *, ULONG, PSECURITY_DESCRIPTOR, A_MSG *, PULONG, A_MSG_ATTR *, A_MSG_ATTR *, PLARGE_INTEGER));
UDECL(NTSTATUS, NtAlpcAcceptConnectPort, (PHANDLE, HANDLE, ULONG, POBJECT_ATTRIBUTES, A_PORT_ATTR *, PVOID, A_MSG *, A_MSG_ATTR *, BOOLEAN));
UDECL(NTSTATUS, NtAlpcSendWaitReceivePort, (HANDLE, ULONG, A_MSG *, A_MSG_ATTR *, A_MSG *, PSIZE_T, A_MSG_ATTR *, PLARGE_INTEGER));
UDECL(NTSTATUS, NtAlpcDisconnectPort, (HANDLE, ULONG));
UDECL(NTSTATUS, NtAlpcQueryInformation, (HANDLE, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtAlpcSetInformation, (HANDLE, ULONG, PVOID, ULONG));
UDECL(NTSTATUS, NtAlpcQueryInformationMessage, (HANDLE, A_MSG *, ULONG, PVOID, ULONG, PULONG));
UDECL(NTSTATUS, NtAlpcCreatePortSection, (HANDLE, ULONG, HANDLE, SIZE_T, ALPC_HANDLE_T *, PSIZE_T));
UDECL(NTSTATUS, NtAlpcDeletePortSection, (HANDLE, ULONG, ALPC_HANDLE_T));
UDECL(NTSTATUS, NtAlpcCreateResourceReserve, (HANDLE, ULONG, SIZE_T, ALPC_HANDLE_T *));
UDECL(NTSTATUS, NtAlpcDeleteResourceReserve, (HANDLE, ULONG, ALPC_HANDLE_T));
UDECL(NTSTATUS, NtAlpcCreateSectionView, (HANDLE, ULONG, A_VIEW_ATTR *));
UDECL(NTSTATUS, NtAlpcDeleteSectionView, (HANDLE, ULONG, PVOID));
UDECL(NTSTATUS, NtAlpcCreateSecurityContext, (HANDLE, ULONG, A_SEC_ATTR *));
UDECL(NTSTATUS, NtAlpcDeleteSecurityContext, (HANDLE, ULONG, ALPC_HANDLE_T));
UDECL(NTSTATUS, NtAlpcRevokeSecurityContext, (HANDLE, ULONG, ALPC_HANDLE_T));
UDECL(NTSTATUS, NtAlpcCancelMessage, (HANDLE, ULONG, A_CTX_ATTR *));
UDECL(NTSTATUS, NtAlpcImpersonateClientOfPort, (HANDLE, A_MSG *, PVOID));
UDECL(NTSTATUS, NtAlpcImpersonateClientContainerOfPort, (HANDLE, A_MSG *, ULONG));
UDECL(NTSTATUS, NtAlpcOpenSenderProcess, (PHANDLE, HANDLE, A_MSG *, ULONG, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtAlpcOpenSenderThread, (PHANDLE, HANDLE, A_MSG *, ULONG, ACCESS_MASK, POBJECT_ATTRIBUTES));
UDECL(NTSTATUS, NtClose, (HANDLE));

#define S(x) ((NTSTATUS)(x))
#define NT(f) UN(f)

/* Build a port name unique to this process and test. */
static inline void a_name(WCHAR *buf, size_t cap, const char *tag)
{
    swprintf(buf, cap, L"\\RPC Control\\t_alpc_%lu_%S", GetCurrentProcessId(), tag);
}
static inline void a_oa(OBJECT_ATTRIBUTES *oa, UNICODE_STRING *us, WCHAR *name, ULONG attrs)
{
    us->Buffer = name; us->Length = (USHORT)(wcslen(name) * 2); us->MaximumLength = us->Length + 2;
    memset(oa, 0, sizeof *oa);
    oa->Length = sizeof *oa; oa->ObjectName = us; oa->Attributes = attrs;
}
#endif
