/*
 * comms.c — user<->kernel port. The agent connects with
 * FilterConnectCommunicationPort(L"\\XemsFltPort"). GET_STATUS is answered
 * synchronously; tamper events are pushed with FltSendMessage.
 */
#include "xemsflt.h"
#include <ntstrsafe.h>

static NTSTATUS XemsConnect(PFLT_PORT ClientPort, PVOID ServerCookie,
                            PVOID ConnectionContext, ULONG SizeOfContext,
                            PVOID *ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ServerCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);
    g_Xems.ClientPort = ClientPort;
    /* Auto-protect the connecting agent's PID. */
    XemsRegisterProtectedPid(PsGetCurrentProcessId());
    return STATUS_SUCCESS;
}

static VOID XemsDisconnect(PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(g_Xems.Filter, &g_Xems.ClientPort);
    g_Xems.ClientPort = NULL;
}

/* Request/response: agent -> kernel (FilterSendMessage). */
static NTSTATUS XemsMessage(PVOID ConnectionCookie, PVOID InputBuffer,
                            ULONG InputBufferLength, PVOID OutputBuffer,
                            ULONG OutputBufferLength, PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    *ReturnOutputBufferLength = 0;
    if (InputBufferLength < sizeof(XEMSFLT_REQUEST)) return STATUS_INVALID_PARAMETER;

    XEMSFLT_REQUEST req;
    RtlCopyMemory(&req, InputBuffer, sizeof(req));

    switch (req.Command) {
    case XemsFltCmdGetStatus: {
        if (OutputBufferLength < sizeof(XEMSFLT_STATUS)) return STATUS_BUFFER_TOO_SMALL;
        XEMSFLT_STATUS st = { 0 };
        st.Version   = 1;
        st.Active    = (ULONG)g_Xems.Active;
        st.DeniedOps = (ULONGLONG)g_Xems.DeniedOps;
        RtlCopyMemory(OutputBuffer, &st, sizeof(st));
        *ReturnOutputBufferLength = sizeof(st);
        return STATUS_SUCCESS;
    }
    case XemsFltCmdSetPolicy:
        XemsRegisterProtectedPid(ULongToHandle(req.Arg));
        return STATUS_SUCCESS;
    case XemsFltCmdPing:
        return STATUS_SUCCESS;
    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

NTSTATUS XemsCommsInit(PFLT_FILTER Filter)
{
    XemsProtectInit();
    UNICODE_STRING name; RtlInitUnicodeString(&name, XEMSFLT_PORT_NAME);

    PSECURITY_DESCRIPTOR sd = NULL;
    NTSTATUS status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) return status;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &name,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

    status = FltCreateCommunicationPort(Filter, &g_Xems.ServerPort, &oa, NULL,
        XemsConnect, XemsDisconnect, XemsMessage, 1 /* max connections */);
    FltFreeSecurityDescriptor(sd);
    return status;
}

VOID XemsCommsTeardown(VOID)
{
    if (g_Xems.ServerPort) { FltCloseCommunicationPort(g_Xems.ServerPort); g_Xems.ServerPort = NULL; }
}

/* Push a tamper event to the connected agent (best-effort, short timeout). */
VOID XemsPushEvent(ULONG Kind, ULONG ActorPid, PCWSTR Target)
{
    if (g_Xems.ClientPort == NULL) return;
    XEMSFLT_EVENT evt = { 0 };
    evt.Kind = Kind; evt.ActorPid = ActorPid;
    LARGE_INTEGER qpc = KeQueryPerformanceCounter(NULL);
    evt.TimestampQpc = (ULONGLONG)qpc.QuadPart;
    if (Target) RtlStringCchCopyW(evt.Target, RTL_NUMBER_OF(evt.Target), Target);

    LARGE_INTEGER timeout; timeout.QuadPart = -10 * 1000 * 100; /* 100ms relative */
    FltSendMessage(g_Xems.Filter, &g_Xems.ClientPort, &evt, sizeof(evt),
                   NULL, NULL, &timeout);
}
