//go:build windows

package main

import (
	"bufio"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func readPasswordLine() (string, error) {
	handle := windows.Handle(os.Stdin.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		reader := bufio.NewReader(os.Stdin)
		value, readErr := reader.ReadString('\n')
		return strings.TrimRight(value, "\r\n"), readErr
	}
	if err := windows.SetConsoleMode(handle, mode &^ windows.ENABLE_ECHO_INPUT); err != nil {
		return "", err
	}
	defer windows.SetConsoleMode(handle, mode)

	reader := bufio.NewReader(os.Stdin)
	value, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(value, "\r\n"), nil
}
