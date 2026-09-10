/*
 * xemsflt_ioctl.h — PUBLIC user<->kernel ABI for the XEMS tamper-protection
 * MiniFilter driver (xemsflt.sys). This is the ONLY header the Go agent mirrors
 * (see agent/internal/tamperprotect/driverclient_windows.go). Keep struct layouts
 * fixed-size and packed; the Go side hard-codes the layout.
 */
#pragma once

/* FltCreateCommunicationPort object name. Userland connects via
 * FilterConnectCommunicationPort(L"\\XemsFltPort", ...). */
#define XEMSFLT_PORT_NAME   L"\\XemsFltPort"

/* Message opcodes: userland -> kernel (request/response). */
typedef enum _XEMSFLT_CMD {
    XemsFltCmdGetStatus = 1,   /* agent asks: are you loaded/active? counters? */
    XemsFltCmdSetPolicy = 2,   /* agent pushes a protected PID */
    XemsFltCmdPing      = 3,   /* liveness */
} XEMSFLT_CMD;

#pragma pack(push, 1)

/* Request header sent by userland (FilterSendMessage input buffer). */
typedef struct _XEMSFLT_REQUEST {
    unsigned long Command;      /* XEMSFLT_CMD */
    unsigned long Arg;          /* command-specific (e.g. a PID to protect) */
} XEMSFLT_REQUEST;

/* Status reply (FilterSendMessage output buffer for XemsFltCmdGetStatus). */
typedef struct _XEMSFLT_STATUS {
    unsigned long      Version;         /* driver ABI version */
    unsigned long      Active;          /* 1 = filtering active */
    unsigned long      ProtectedPids;   /* count of PIDs under Ob protection */
    unsigned long      ProtectedPaths;  /* count of protected file/registry paths */
    unsigned long long DeniedOps;       /* cumulative denied tamper operations */
} XEMSFLT_STATUS;

/* Kernel -> userland pushed tamper event kinds. */
typedef enum _XEMSFLT_EVENT_KIND {
    XemsFltEvtProcessTerminateBlocked = 1,
    XemsFltEvtHandleStripped          = 2,
    XemsFltEvtFileWriteBlocked        = 3,
    XemsFltEvtFileDeleteBlocked       = 4,
    XemsFltEvtRegistryBlocked         = 5,
} XEMSFLT_EVENT_KIND;

/* Kernel -> userland pushed tamper event (FilterGetMessage payload, follows the
 * FILTER_MESSAGE_HEADER that the filter manager prepends). */
typedef struct _XEMSFLT_EVENT {
    unsigned long      Kind;            /* XEMSFLT_EVENT_KIND */
    unsigned long      ActorPid;        /* process that attempted the tamper */
    unsigned long long TimestampQpc;    /* KeQueryPerformanceCounter at detection */
    unsigned short     Target[260];     /* null-terminated: path or "PID:<n>" (UTF-16) */
} XEMSFLT_EVENT;

#pragma pack(pop)
