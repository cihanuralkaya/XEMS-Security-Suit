/*
 * protect.c — WHAT is protected. The agent registers its own PID (and watchdog's)
 * at connect time (SetPolicy), with static fallbacks by image/config path suffix.
 * A production build would harden path canonicalization, add CmRegisterCallbackEx
 * for registry protection, and lock the table under a proper lock.
 */
#include "xemsflt.h"

#define XEMS_MAX_PIDS 8
static HANDLE     g_Pids[XEMS_MAX_PIDS];
static ULONG      g_PidCount;
static FAST_MUTEX g_Lock;

/* Static fallback: protect by well-known image/config path suffixes even before
 * the agent connects. Adjust to the real install path (e.g. %ProgramFiles%\XEMS\). */
static const WCHAR *kProtectedSuffixes[] = {
    L"\\xems-agent.exe",
    L"\\xems-watchdog.exe",
    L"\\xems\\agent.conf",
    L"\\xems\\config.yaml",
};

VOID XemsProtectInit(VOID) { ExInitializeFastMutex(&g_Lock); g_PidCount = 0; }

VOID XemsRegisterProtectedPid(HANDLE Pid)
{
    ExAcquireFastMutex(&g_Lock);
    for (ULONG i = 0; i < g_PidCount; ++i)
        if (g_Pids[i] == Pid) { ExReleaseFastMutex(&g_Lock); return; }
    if (g_PidCount < XEMS_MAX_PIDS) g_Pids[g_PidCount++] = Pid;
    ExReleaseFastMutex(&g_Lock);
}

BOOLEAN XemsIsProtectedProcess(HANDLE Pid)
{
    BOOLEAN found = FALSE;
    ExAcquireFastMutex(&g_Lock);
    for (ULONG i = 0; i < g_PidCount; ++i)
        if (g_Pids[i] == Pid) { found = TRUE; break; }
    ExReleaseFastMutex(&g_Lock);
    return found;
}

static BOOLEAN EndsWithCI(PCUNICODE_STRING s, const WCHAR *suffix)
{
    UNICODE_STRING suf; RtlInitUnicodeString(&suf, suffix);
    if (s->Length < suf.Length) return FALSE;
    UNICODE_STRING tail;
    tail.Buffer = (PWCH)((PUCHAR)s->Buffer + s->Length - suf.Length);
    tail.Length = suf.Length; tail.MaximumLength = suf.Length;
    return RtlEqualUnicodeString(&tail, &suf, TRUE); /* case-insensitive */
}

BOOLEAN XemsIsProtectedFilePath(PCUNICODE_STRING Path)
{
    for (ULONG i = 0; i < ARRAYSIZE(kProtectedSuffixes); ++i)
        if (EndsWithCI(Path, kProtectedSuffixes[i])) return TRUE;
    return FALSE;
}

BOOLEAN XemsIsProtectedImagePath(PCUNICODE_STRING Path) { return XemsIsProtectedFilePath(Path); }

/* Registry protection is enforced via CmRegisterCallbackEx in a full build;
 * this documents the protected key roots. */
BOOLEAN XemsIsProtectedRegistryPath(PCUNICODE_STRING Path)
{
    return EndsWithCI(Path, L"\\Services\\xemsflt") ||
           EndsWithCI(Path, L"\\XEMS");
}
