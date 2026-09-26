package main

import (
	"errors"
	"strings"
)

func readLoginCredentials() (string, string, error) {
	username, password, err := readLoginCredentialsPlatform()
	if err != nil {
		return "", "", err
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return "", "", errors.New("BPC username is empty")
	}
	if password == "" {
		return "", "", errors.New("BPC password is empty")
	}
	return username, password, nil
}
