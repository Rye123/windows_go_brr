#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#define BUF_LEN 255

typedef struct
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA_UNDOC;

typedef struct
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	_ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY_UNDOC;

typedef NTSTATUS(NTAPI* fpNtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength
	);

int main()
{
	// Load NtQueryInformationProcess
	const char aNtdllStr[] = "ntdll.dll";
	HMODULE hNtdll = GetModuleHandleA(aNtdllStr);
	if (hNtdll == NULL)
		hNtdll = LoadLibraryA(aNtdllStr);
	if (hNtdll == NULL) {
		fprintf(stderr, "Failed to load library %s\n", aNtdllStr);
		return 1;
	}

	fpNtQueryInformationProcess NtQueryInformationProcess = (fpNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (NtQueryInformationProcess == NULL) {
		fprintf(stderr, "Failed to load NtQueryInformationProcess\n");
		return 1;
	}

	// Initialisation
	char buf[BUF_LEN];
	int pid;
	HANDLE hProc;

	// Obtain PID and process handle
	printf("Enter PID: ");
	fgets(buf, BUF_LEN, stdin);
	pid = atoi(buf);
	hProc = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (!hProc) {
		fprintf(stderr, "Failed to open process with PID %d\n", pid);
		return 1;
	}

	// Get PEB
	PROCESS_BASIC_INFORMATION pbi = { 0 };
	NTSTATUS ntResult = NtQueryInformationProcess(hProc, ProcessBasicInformation, (PVOID)&pbi, sizeof(pbi));
	if (NT_ERROR(ntResult) || !pbi.PebBaseAddress) {
		fprintf(stderr, "Failed to query process information. Error Code: %x\n", ntResult);
		return 1;
	}
	
	PEB peb = { 0 };
	SIZE_T bytesRead;
	if (!ReadProcessMemory(hProc, (LPCVOID)pbi.PebBaseAddress, &peb, sizeof(PEB), &bytesRead)) {
		fprintf(stderr, "Failed to read process memory. Error: %X\n", GetLastError());
		return 1;
	}
	printf("LDR pointer: %p\n", peb.Ldr);

	// Get list data
	PEB_LDR_DATA_UNDOC pebLdrData = { 0 };
	if (!ReadProcessMemory(hProc, (LPCVOID)peb.Ldr, &pebLdrData, sizeof(PEB_LDR_DATA_UNDOC), &bytesRead)) {
		fprintf(stderr, "Failed to read process memory for PEB LDR Data. Error: %X\n", GetLastError());
		return 1;
	}

	// Read list
	LIST_ENTRY* head = pebLdrData.InLoadOrderModuleList.Flink;
	LIST_ENTRY* entry = pebLdrData.InLoadOrderModuleList.Flink;
	unsigned int numEntries = 0;

	do {
		// Get DLL Information
		LDR_DATA_TABLE_ENTRY_UNDOC ldrEntry = { 0 };
		if (!ReadProcessMemory(hProc, (LPCVOID)entry, &ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY_UNDOC), &bytesRead)) {
			fprintf(stderr, "Failed to read process memory for LDR entry. Error: %X\n", GetLastError());
			return 1;
		}

		// Update entry
		numEntries++;
		entry = ldrEntry.InLoadOrderLinks.Flink;

		// Report Entry
		USHORT strLen = ldrEntry.FullDllName.Length;
		if (strLen > 0) {
			PWSTR dllName = (PWSTR)malloc(strLen * sizeof(WCHAR));
			if (!ReadProcessMemory(hProc, (LPCVOID)ldrEntry.FullDllName.Buffer, &(*dllName), strLen * sizeof(WCHAR), &bytesRead)) {
				fprintf(stderr, "Failed to read process memory for DLL name. Error: %X\n", GetLastError());
				return 1;
			}
			wprintf(L"DLL %lu:\n\tBase address: %p\n\tFull Name: %s\n", numEntries, ldrEntry.DllBase, dllName);
		}
		else {
			printf("DLL %lu:\n\tBase address: %p\n", numEntries, ldrEntry.DllBase);
		}
	} while (entry != head);
	printf("Entry Count: %u\n", numEntries);
}
