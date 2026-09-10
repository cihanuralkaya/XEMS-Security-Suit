/*
 * xemsflt.h — internal declarations for the XEMS tamper-protection MiniFilter.
 * SKELETON (see driver/xemsflt/README.md): correctness of intent over exhaustive
 * completeness. Built by the WDK/EWDK only — never by the Go CI.
 */
#pragma once
#include <fltKernel.h>
#include <dontuse.h>
#include "..\inc\xemsflt_ioctl.h"

#define XEMSFLT_POOL_TAG 'tFmX'   /* 'XmFt' */

/* Registered filter altitude — PLACEHOLDER. A production altitude must be
 * requested from Microsoft (fsfcomm@microsoft.com; see README). 385200 is in the
 * FSFilter Anti-Virus range and is fine for DEV/test-signed builds only. */
#define XEMSFLT_ALTITUDE L"385200"

/* Global driver state. */
typedef struct _XEMSFLT_GLOBALS {
    PFLT_FILTER    Filter;        /* from FltRegisterFilter */
    PFLT_PORT      ServerPort;    /* FltCreateCommunicationPort server */
    PFLT_PORT      ClientPort;    /* single connected agent */
    PVOID          ObHandle;      /* ObRegisterCallbacks registration */
    volatile LONG  Active;
    volatile LONG64 DeniedOps;
} XEMSFLT_GLOBALS;

extern XEMSFLT_GLOBALS g_Xems;

/* protect.c — policy */
VOID    XemsProtectInit(VOID);
BOOLEAN XemsIsProtectedProcess(HANDLE Pid);
BOOLEAN XemsIsProtectedImagePath(PCUNICODE_STRING Path);   /* agent/watchdog .exe */
BOOLEAN XemsIsProtectedFilePath(PCUNICODE_STRING Path);    /* binary/config */
BOOLEAN XemsIsProtectedRegistryPath(PCUNICODE_STRING Path);
VOID    XemsRegisterProtectedPid(HANDLE Pid);

/* comms.c — communication port */
NTSTATUS XemsCommsInit(PFLT_FILTER Filter);
VOID     XemsCommsTeardown(VOID);
VOID     XemsPushEvent(ULONG Kind, ULONG ActorPid, PCWSTR Target);

/* obcallbacks.c — process-kill protection */
NTSTATUS XemsObInit(VOID);
VOID     XemsObTeardown(VOID);
