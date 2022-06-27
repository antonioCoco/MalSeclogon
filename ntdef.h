#pragma once

// most of this header code took from --> https://github.com/hfiref0x/NtCall64/blob/master/Source/NtCall64/ntos.h
// credits to @hfiref0x

#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define STATUS_INSUFFICIENT_RESOURCES 0xC0000009A
#define STATUS_NOT_FOUND 0xC0000225
#define SystemHandleInformation 16

#ifndef RtlOffsetToPointer
#define RtlOffsetToPointer(Base, Offset)  ((PCHAR)( ((PCHAR)(Base)) + ((ULONG_PTR)(Offset))  ))
#endif

#ifndef ALIGN_UP_TYPE
#define ALIGN_UP_TYPE(Address, Align) (((ULONG_PTR)(Address) + (Align) - 1) & ~((Align) - 1))
#endif

#ifndef ALIGN_UP
#define ALIGN_UP(Address, Type) ALIGN_UP_TYPE(Address, sizeof(Type))
#endif

#ifndef RTL_CONSTANT_STRING
char _RTL_CONSTANT_STRING_type_check(const void* s);
#define _RTL_CONSTANT_STRING_remove_const_macro(s) (s)
#define RTL_CONSTANT_STRING(s) \
{ \
    sizeof( s ) - sizeof( (s)[0] ), \
    sizeof( s ) / sizeof(_RTL_CONSTANT_STRING_type_check(s)), \
    _RTL_CONSTANT_STRING_remove_const_macro(s) \
}
#endif

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define OBJECT_TYPES_FIRST_ENTRY(ObjectTypes) (POBJECT_TYPE_INFORMATION)\
    RtlOffsetToPointer(ObjectTypes, ALIGN_UP(sizeof(OBJECT_TYPES_INFORMATION), ULONG_PTR))

#define OBJECT_TYPES_NEXT_ENTRY(ObjectType) (POBJECT_TYPE_INFORMATION)\
    RtlOffsetToPointer(ObjectType, sizeof(OBJECT_TYPE_INFORMATION) + \
    ALIGN_UP(ObjectType->TypeName.MaximumLength, ULONG_PTR))

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _GDI_TEB_BATCH
{
	ULONG Offset;
	HANDLE HDC;
	ULONG Buffer[310];
} GDI_TEB_BATCH;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _TEB
{
	NT_TIB NtTib;
	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PVOID ProcessEnvironmentBlock;
	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID CsrClientThread;
	PVOID Win32ThreadInfo;
	ULONG User32Reserved[26];
	ULONG UserReserved[5];
	PVOID WOW32Reserved;
	LCID CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	PVOID SystemReserved1[54];
	LONG ExceptionCode;
	UCHAR Padding0[4];
	PVOID ActivationContextStackPointer;
	UCHAR SpareBytes[24];
	ULONG TxFsContext;
	GDI_TEB_BATCH GdiTebBatch;
	CLIENT_ID RealClientId;
	PVOID GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	PVOID GdiThreadLocalInfo;
	SIZE_T Win32ClientInfo[62];
	PVOID glDispatchTable[233];
	SIZE_T glReserved1[29];
	PVOID glReserved2;
	PVOID glSectionInfo;
	PVOID glSection;
	PVOID glTable;
	PVOID glCurrentRC;
	PVOID glContext;
	ULONG LastStatusValue;
	UCHAR Padding2[4];
	UNICODE_STRING StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];
	UCHAR Padding3[6];
	PVOID DeallocationStack;
	PVOID TlsSlots[64];
	LIST_ENTRY TlsLinks;
	PVOID Vdm;
	PVOID ReservedForNtRpc;
	PVOID DbgSsReserved[2];
	ULONG HardErrorMode;
	UCHAR Padding4[4];
	PVOID Instrumentation[11];
	GUID ActivityId;
	PVOID SubProcessTag;
	PVOID EtwLocalData;
	PVOID EtwTraceData;
	PVOID WinSockData;
	ULONG GdiBatchCount;
	union
	{
		PROCESSOR_NUMBER CurrentIdealProcessor;
		ULONG32 IdealProcessorValue;
		struct
		{
			UCHAR ReservedPad0;
			UCHAR ReservedPad1;
			UCHAR ReservedPad2;
			UCHAR IdealProcessor;
		};
	};
	ULONG GuaranteedStackBytes;
	UCHAR Padding5[4];
	PVOID ReservedForPerf;
	PVOID ReservedForOle;
	ULONG WaitingOnLoaderLock;
	UCHAR Padding6[4];
	PVOID SavedPriorityState;
	ULONG_PTR SoftPatchPtr1;
	ULONG_PTR ThreadPoolData;
	PVOID* TlsExpansionSlots;
	PVOID DeallocationBStore;
	PVOID BStoreLimit;
	ULONG ImpersonationLocale;
	ULONG IsImpersonating;
	PVOID NlsCache;
	PVOID pShimData;
	ULONG HeapVirtualAffinity;
	UCHAR Padding7[4];
	HANDLE CurrentTransactionHandle;
	PVOID ActiveFrame;
	PVOID FlsData;
	PVOID PreferredLanguages;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;
	union
	{
		USHORT CrossTebFlags;
		struct
		{
			unsigned __int16 SpareCrossTebBits : 16;
		};
	};
	union
	{
		USHORT SameTebFlags;
		struct
		{
			unsigned __int16 DbgSafeThunkCall : 1;
			unsigned __int16 DbgInDebugPrint : 1;
			unsigned __int16 DbgHasFiberData : 1;
			unsigned __int16 DbgSkipThreadAttach : 1;
			unsigned __int16 DbgWerInShipAssertCode : 1;
			unsigned __int16 DbgIssuedInitialBp : 1;
			unsigned __int16 DbgClonedThread : 1;
			unsigned __int16 SpareSameTebBits : 9;
		};
	};
	PVOID TxnScopeEnterCallback;
	PVOID TxnScopeExitCallback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	ULONG SpareUlong0;
	PVOID ResourceRetValue;
} TEB, * PTEB;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _OBJECT_TYPES_INFORMATION {
	ULONG NumberOfTypes;
} OBJECT_TYPES_INFORMATION, * POBJECT_TYPES_INFORMATION;

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectTypesInformation,
	ObjectHandleFlagInformation,
	ObjectSessionInformation,
	ObjectSessionObjectInformation,
	MaxObjectInfoClass
} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION_V2 {
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	UCHAR TypeIndex;
	CHAR ReservedByte;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION_V2, * POBJECT_TYPE_INFORMATION_V2;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef enum _FILE_INFORMATION_CLASS {
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,                   // 2
	FileBothDirectoryInformation,                   // 3
	FileBasicInformation,                           // 4
	FileStandardInformation,                        // 5
	FileInternalInformation,                        // 6
	FileEaInformation,                              // 7
	FileAccessInformation,                          // 8
	FileNameInformation,                            // 9
	FileRenameInformation,                          // 10
	FileLinkInformation,                            // 11
	FileNamesInformation,                           // 12
	FileDispositionInformation,                     // 13
	FilePositionInformation,                        // 14
	FileFullEaInformation,                          // 15
	FileModeInformation,                            // 16
	FileAlignmentInformation,                       // 17
	FileAllInformation,                             // 18
	FileAllocationInformation,                      // 19
	FileEndOfFileInformation,                       // 20
	FileAlternateNameInformation,                   // 21
	FileStreamInformation,                          // 22
	FilePipeInformation,                            // 23
	FilePipeLocalInformation,                       // 24
	FilePipeRemoteInformation,                      // 25
	FileMailslotQueryInformation,                   // 26
	FileMailslotSetInformation,                     // 27
	FileCompressionInformation,                     // 28
	FileObjectIdInformation,                        // 29
	FileCompletionInformation,                      // 30
	FileMoveClusterInformation,                     // 31
	FileQuotaInformation,                           // 32
	FileReparsePointInformation,                    // 33
	FileNetworkOpenInformation,                     // 34
	FileAttributeTagInformation,                    // 35
	FileTrackingInformation,                        // 36
	FileIdBothDirectoryInformation,                 // 37
	FileIdFullDirectoryInformation,                 // 38
	FileValidDataLengthInformation,                 // 39
	FileShortNameInformation,                       // 40
	FileIoCompletionNotificationInformation,        // 41
	FileIoStatusBlockRangeInformation,              // 42
	FileIoPriorityHintInformation,                  // 43
	FileSfioReserveInformation,                     // 44
	FileSfioVolumeInformation,                      // 45
	FileHardLinkInformation,                        // 46
	FileProcessIdsUsingFileInformation,             // 47
	FileNormalizedNameInformation,                  // 48
	FileNetworkPhysicalNameInformation,             // 49
	FileIdGlobalTxDirectoryInformation,             // 50
	FileIsRemoteDeviceInformation,                  // 51
	FileUnusedInformation,                          // 52
	FileNumaNodeInformation,                        // 53
	FileStandardLinkInformation,                    // 54
	FileRemoteProtocolInformation,                  // 55

	//
	//  These are special versions of these operations (defined earlier)
	//  which can be used by kernel mode drivers only to bypass security
	//  access checks for Rename and HardLink operations.  These operations
	//  are only recognized by the IOManager, a file system should never
	//  receive these.
	//

	FileRenameInformationBypassAccessCheck,         // 56
	FileLinkInformationBypassAccessCheck,           // 57

	//
	// End of special information classes reserved for IOManager.
	//

	FileVolumeNameInformation,                      // 58
	FileIdInformation,                              // 59
	FileIdExtdDirectoryInformation,                 // 60
	FileReplaceCompletionInformation,               // 61
	FileHardLinkFullIdInformation,                  // 62
	FileIdExtdBothDirectoryInformation,             // 63
	FileDispositionInformationEx,                   // 64
	FileRenameInformationEx,                        // 65
	FileRenameInformationExBypassAccessCheck,       // 66
	FileDesiredStorageClassInformation,             // 67
	FileStatInformation,                            // 68
	FileMemoryPartitionInformation,                 // 69
	FileStatLxInformation,                          // 70
	FileCaseSensitiveInformation,                   // 71
	FileLinkInformationEx,                          // 72
	FileLinkInformationExBypassAccessCheck,         // 73
	FileStorageReserveIdInformation,                // 74
	FileCaseSensitiveInformationForceAccessCheck,   // 75
	FileKnownFolderInformation,   // 76

	FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _FILE_PROCESS_IDS_USING_FILE_INFORMATION
{
	ULONG NumberOfProcessIdsInList;
	ULONG_PTR ProcessIdList[1];
} FILE_PROCESS_IDS_USING_FILE_INFORMATION, * PFILE_PROCESS_IDS_USING_FILE_INFORMATION;

typedef struct _THREAD_PARAMETERS
{
	int pid;
	wchar_t* cmdline;
} THREAD_PARAMETERS;

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* pNtQueryObject)(_In_opt_ HANDLE Handle, _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass, _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation, _In_ ULONG ObjectInformationLength, _Out_opt_ PULONG ReturnLength);
typedef NTSTATUS(NTAPI* pRtlCompareUnicodeString)(_In_ PCUNICODE_STRING String1, _In_ PCUNICODE_STRING String2, _In_ BOOLEAN CaseInSensitive);
typedef NTSTATUS(NTAPI* pNtCreateProcessEx)(PHANDLE ProcessHandle, ACCESS_MASK  DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle OPTIONAL, HANDLE DebugPort OPTIONAL, HANDLE ExceptionPort OPTIONAL, BOOLEAN InJob);
typedef BOOL(WINAPI* pMiniDumpWriteDump)(HANDLE hProcess, DWORD dwPid, HANDLE hFile, int DumpType, PVOID ExceptionParam, PVOID UserStreamParam, PVOID CallbackParam);
typedef NTSTATUS(NTAPI* pNtQueryInformationFile)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
