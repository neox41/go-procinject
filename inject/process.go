package inject

import (
	"golang.org/x/sys/windows"
	"syscall"

	"go-procinject/config"
)

func CreateProcess() *syscall.ProcessInformation{
	var si syscall.StartupInfo
	var pi syscall.ProcessInformation

	commandLine, err := syscall.UTF16PtrFromString(config.Target)

	if err != nil {
		panic(err)
	}

	err = syscall.CreateProcess(
		nil,
		commandLine,
		nil,
		nil,
		false,
		windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW,
		nil,
		nil,
		&si,
		&pi)

	if err != nil {
		panic(err)
	}

	return &pi
}

