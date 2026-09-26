//go:build !windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func readLoginCredentialsPlatform() (string, string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("BPC username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return "", "", fmt.Errorf("read username: %w", err)
	}

	fmt.Print("BPC password: ")
	password, err := reader.ReadString('\n')
	fmt.Println()
	if err != nil {
		return "", "", fmt.Errorf("read password: %w", err)
	}
	return strings.TrimSpace(username), strings.TrimRight(password, "\r\n"), nil
}
