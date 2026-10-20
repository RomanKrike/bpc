//go:build windows

package main

import (
	"errors"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func startP2PService() error { return p2pServiceAction(true) }
func stopP2PService() error  { return p2pServiceAction(false) }

func p2pServiceOwned(commandLine, expected string) bool {
	args, err := windows.DecomposeCommandLine(commandLine)
	return err == nil && len(args) == 2 && samePath(args[0], expected) && args[1] == "run-service"
}

func p2pServiceAction(start bool) error {
	_, exe, _, err := installPaths()
	if err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer service.Close()
	config, err := service.Config()
	if err != nil {
		return err
	}
	if !p2pServiceOwned(config.BinaryPathName, exe) {
		return errors.New("refusing to restart a service not owned by the installed BPC Agent")
	}
	status, err := service.Query()
	if err != nil {
		return err
	}
	target := svc.Stopped
	if start {
		target = svc.Running
	}
	if status.State == target {
		return nil
	}
	if start {
		err = service.Start()
	} else {
		_, err = service.Control(svc.Stop)
	}
	if err != nil {
		return err
	}
	return waitServiceState(service, target, 20*time.Second)
}
