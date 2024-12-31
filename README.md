# InDirect Syscall Injection - Advanced Malware Development 

# Overview
This repository provides an implementation of Indirect Syscall Injection, an advanced technique for stealthy process injection and evasion.

# Features
Dynamically resolves syscall numbers for commonly used APIs
Implements custom assembly routines for executing syscalls indirectly
Demonstrates injection by allocating memory, writing shellcode, and creating threads in a target process
Includes cleanup routines for resource deallocation

# Example Output:
[+] Got a handle to the process: 1234

[+] Allocated buffer to memory at: 0x0000021234567000

[+] Wrote to the memory

[+] Changed allocated buffer protection to PAGE_EXECUTE_READ

[+] Thread Created! Routine Started.

[+] Thread Finished! .. Happy Hacking!!

# Disclaimer
This code is intended for educational purposes only. Misuse of this repository may lead to legal consequences. Ensure you have explicit permission before running this on any system.

# Acknowledgments
Special thanks to Crow for inspiring this series and for the detailed explanations of syscall injection techniques. Check out Crow's YouTube channel for more insights into malware development.

# License
This project is licensed under the MIT License - see the LICENSE file for details.
