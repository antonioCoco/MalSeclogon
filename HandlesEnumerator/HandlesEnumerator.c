#include "windows.h"
#include "stdio.h"
#include "ntdef.h"
#include "psapi.h"

BOOL SetPrivilege(HANDLE hToken, wchar_t* lpszPrivilege, BOOL bEnablePrivilege);
void EnableDebugPrivilege();
void EnumerateHandles(DWORD targetPid);
NTSTATUS QueryObjectTypesInfo(__out POBJECT_TYPES_INFORMATION* TypesInfo);
NTSTATUS GetTypeIndexByName(__in PCUNICODE_STRING TypeName, __out PULONG TypeIndex);

int wmain(int argc, wchar_t** argv)
{
	int targetPid = -1;
	if (argc <= 1) {
		printf("You must specify the PID of the target process");
		exit(-1);
	}
	targetPid = _wtoi(argv[1]);
	EnableDebugPrivilege();
	EnumerateHandles(targetPid);
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

void EnableDebugPrivilege() {
	HANDLE currentProcessToken = NULL;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &currentProcessToken);
	if (!SetPrivilege(currentProcessToken, L"SeDebugPrivilege", TRUE)) {
		printf("SetPrivilege failed to enable SeDebugPrivilege. Run it as an Administrator. Exiting...\n");
		exit(-1);
	}
	CloseHandle(currentProcessToken);
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

void EnumerateHandles(DWORD targetPid)
{
	PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
	DWORD handleInfoSize = 0x10000;
	NTSTATUS status;
	ULONG processTypeIndex;
	UNICODE_STRING processTypeName = RTL_CONSTANT_STRING(L"Process");
	HANDLE hHostProcess, dupedHandle;
	DWORD processId;
	wchar_t processName[MAX_PATH];
	RtlZeroMemory(processName, MAX_PATH * 2);
	status = GetTypeIndexByName(&processTypeName, &processTypeIndex);
	if (!NT_SUCCESS(status)) {
		printf("GetTypeIndexByName failed 0x%08x\n", status);
		return;
	}
	pNtQuerySystemInformation NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtQuerySystemInformation");
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	for (DWORD i = 0; i < handleInfo->HandleCount; i++) {
		if (handleInfo->Handles[i].ObjectTypeIndex == processTypeIndex) {
			hHostProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, handleInfo->Handles[i].UniqueProcessId);
			if (hHostProcess == NULL) continue;
			if (DuplicateHandle(hHostProcess, (HANDLE)handleInfo->Handles[i].HandleValue, GetCurrentProcess(), &dupedHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
				processId = GetProcessId(dupedHandle);
				if (processId == targetPid) {
					GetModuleBaseNameW(hHostProcess, NULL, processName, MAX_PATH);
					printf("Found opened process handle 0x%04x to target PID %d in process %S(PID:%d)\n", handleInfo->Handles[i].HandleValue, targetPid, processName, handleInfo->Handles[i].UniqueProcessId);
					RtlZeroMemory(processName, MAX_PATH*2);
				}
				CloseHandle(dupedHandle);
			}
			dupedHandle = 0;
			CloseHandle(hHostProcess);
			hHostProcess = NULL;
		}
	}
	free(handleInfo);
}
