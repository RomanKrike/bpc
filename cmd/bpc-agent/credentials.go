package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

func readLoginCredentials() (string, string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("BPC username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return "", "", fmt.Errorf("read username: %w", err)
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return "", "", errors.New("BPC username is empty")
	}

	fmt.Print("BPC password: ")
	password, err := readPasswordLine()
	fmt.Println()
	if err != nil {
		return "", "", fmt.Errorf("read password: %w", err)
	}
	if password == "" {
		return "", "", errors.New("BPC password is empty")
	}
	return username, password, nil
}
