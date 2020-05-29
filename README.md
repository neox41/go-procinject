# go-procinject

Repository with some process injection techniques implemented in Golang.

For each technique, the program does the following steps:

1. Create the target 32-bit process `C:\\Windows\\SysWOW64\\notepad.exe` in suspended and no window mode
2. Allocate RW memory to that target process
3. Write the 32-bit shellcode into that target process
4. Change the memory to RX
5. Execute the MessageBox shellcode

<p align="center">
  <img src="https://github.com/mattiareggiani/go-procinject/blob/master/example.png" height="200">
</p>

## Techniques

- [x] CreateRemoteThread
- [x] NtCreateRemoteThread
- [x] QueueUserAPC
- [x] NtQueueUserAPC
- [x] RtlCreateUserThread
- [x] SetThreadContext
- [x] SetThreadContext with C code