//go:build !windows

package main

import (
	"bufio"
	"os"
	"strings"
)

func readPasswordLine() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	value, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(value, "\r\n"), nil
}
