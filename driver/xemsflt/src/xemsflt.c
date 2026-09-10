/*
 * xemsflt.c — XEMS tamper-protection MiniFilter core.
 * DriverEntry -> FltRegisterFilter -> FltStartFiltering, plus IRP_MJ_CREATE and
 * IRP_MJ_SET_INFORMATION pre-op callbacks that DENY write/delete/rename on the
 * protected agent binary and config. Process-kill protection lives in obcallbacks.c.
 *
 * SKELETON: correctness of intent over exhaustive completeness. Not WHQL-ready.
 * Requires Driver Verifier + QA on a dedicated test VM before any real use.
 */
#include "xemsflt.h"
#include <ntstrsafe.h>

XEMSFLT_GLOBALS g_Xems = { 0 };

DRIVER_INITIALIZE DriverEntry;
NTSTATUS XemsUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS XemsInstanceSetup(PCFLT_RELATED_OBJECTS FltObjects,
                           FLT_INSTANCE_SETUP_FLAGS Flags,
                           DEVICE_TYPE VolumeDeviceType,
                           FLT_FILESYSTEM_TYPE VolumeFilesystemType);
NTSTATUS XemsInstanceQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects,
                                   FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS XemsPreCreate(PFLT_CALLBACK_DATA Data,
                                        PCFLT_RELATED_OBJECTS FltObjects,
                                        PVOID *CompletionContext);
FLT_PREOP_CALLBACK_STATUS XemsPreSetInfo(PFLT_CALLBACK_DATA Data,
                                         PCFLT_RELATED_OBJECTS FltObjects,
                                         PVOID *CompletionContext);

CONST FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    { IRP_MJ_CREATE,          0, XemsPreCreate,  NULL },
    { IRP_MJ_SET_INFORMATION, 0, XemsPreSetInfo, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                          /* Flags */
    NULL,                       /* ContextRegistration */
    g_Callbacks,
    XemsUnload,
    XemsInstanceSetup,
    XemsInstanceQueryTeardown,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_Xems.Filter);
    if (!NT_SUCCESS(status)) return status;

    status = XemsObInit();              /* process-kill protection */
    if (!NT_SUCCESS(status)) goto fail_ob;

    status = XemsCommsInit(g_Xems.Filter); /* user<->kernel port */
    if (!NT_SUCCESS(status)) goto fail_comms;

    status = FltStartFiltering(g_Xems.Filter);
    if (!NT_SUCCESS(status)) goto fail_start;

    InterlockedExchange(&g_Xems.Active, 1);
    return STATUS_SUCCESS;

fail_start:  XemsCommsTeardown();
fail_comms:  XemsObTeardown();
fail_ob:     FltUnregisterFilter(g_Xems.Filter);
    return status;
}

NTSTATUS XemsUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    InterlockedExchange(&g_Xems.Active, 0);
    XemsCommsTeardown();
    XemsObTeardown();
    FltUnregisterFilter(g_Xems.Filter);
    return STATUS_SUCCESS;
}

/* Attach to NTFS/ReFS fixed volumes (agent binary/config live on the system drive). */
NTSTATUS XemsInstanceSetup(PCFLT_RELATED_OBJECTS FltObjects,
                           FLT_INSTANCE_SETUP_FLAGS Flags,
                           DEVICE_TYPE VolumeDeviceType,
                           FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    if (VolumeFilesystemType == FLT_FSTYPE_NTFS ||
        VolumeFilesystemType == FLT_FSTYPE_REFS) {
        return STATUS_SUCCESS;      /* attach */
    }
    return STATUS_FLT_DO_NOT_ATTACH;
}

NTSTATUS XemsInstanceQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects,
                                   FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

static NTSTATUS XemsGetName(PFLT_CALLBACK_DATA Data, PFLT_FILE_NAME_INFORMATION *Out)
{
    return FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, Out);
}

/* PRE-CREATE: deny opens that request delete/write access to a protected file. */
FLT_PREOP_CALLBACK_STATUS XemsPreCreate(PFLT_CALLBACK_DATA Data,
                                        PCFLT_RELATED_OBJECTS FltObjects,
                                        PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;   /* trust kernel-mode callers */

    ACCESS_MASK desired = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    ULONG dispo = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF; /* disposition */
    ULONG copts = Data->Iopb->Parameters.Create.Options;

    BOOLEAN wantsWrite  = (desired & (FILE_WRITE_DATA | FILE_APPEND_DATA |
                                      DELETE | WRITE_DAC | WRITE_OWNER)) != 0;
    BOOLEAN wantsDelete = (copts & FILE_DELETE_ON_CLOSE) != 0 ||
                          dispo == FILE_SUPERSEDE || dispo == FILE_OVERWRITE ||
                          dispo == FILE_OVERWRITE_IF;
    if (!wantsWrite && !wantsDelete)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION ni = NULL;
    if (!NT_SUCCESS(XemsGetName(Data, &ni)) || ni == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    FltParseFileNameInformation(ni);

    FLT_PREOP_CALLBACK_STATUS result = FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (XemsIsProtectedFilePath(&ni->Name)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        InterlockedIncrement64(&g_Xems.DeniedOps);
        XemsPushEvent(wantsDelete ? XemsFltEvtFileDeleteBlocked
                                  : XemsFltEvtFileWriteBlocked,
                      HandleToULong(PsGetCurrentProcessId()), ni->Name.Buffer);
        result = FLT_PREOP_COMPLETE;
    }
    FltReleaseFileNameInformation(ni);
    return result;
}

/* PRE-SET-INFORMATION: deny delete/rename/EOF/allocation changes on a protected file. */
FLT_PREOP_CALLBACK_STATUS XemsPreSetInfo(PFLT_CALLBACK_DATA Data,
                                         PCFLT_RELATED_OBJECTS FltObjects,
                                         PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FILE_INFORMATION_CLASS ic = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    BOOLEAN dangerous =
        ic == FileDispositionInformation   || ic == FileDispositionInformationEx ||
        ic == FileRenameInformation        || ic == FileRenameInformationEx      ||
        ic == FileEndOfFileInformation     || ic == FileAllocationInformation;
    if (!dangerous)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION ni = NULL;
    if (!NT_SUCCESS(XemsGetName(Data, &ni)) || ni == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    FltParseFileNameInformation(ni);

    FLT_PREOP_CALLBACK_STATUS result = FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (XemsIsProtectedFilePath(&ni->Name)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        InterlockedIncrement64(&g_Xems.DeniedOps);
        XemsPushEvent(XemsFltEvtFileDeleteBlocked,
                      HandleToULong(PsGetCurrentProcessId()), ni->Name.Buffer);
        result = FLT_PREOP_COMPLETE;
    }
    FltReleaseFileNameInformation(ni);
    return result;
}
