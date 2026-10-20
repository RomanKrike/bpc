//go:build windows

package main

import (
	"golang.org/x/sys/windows"
	"runtime"
	"strings"
	"unsafe"
)

func showInstallError(err error) {
	text, e := windows.UTF16PtrFromString("Не удалось установить BP Connect.\n\n" + strings.ReplaceAll(err.Error(), "\x00", ""))
	if e != nil {
		return
	}
	title, _ := windows.UTF16PtrFromString("BP Connect")
	// Use a native dialog: no dependency on PowerShell successfully starting.
	box := windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW")
	_, _, _ = box.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), 0x10|0x10000|0x40000)
	runtime.KeepAlive(text)
	runtime.KeepAlive(title)
}
