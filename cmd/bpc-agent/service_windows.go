//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "BPCAgent"

type agentService struct{}

func (agentService) Execute(
	_ []string,
	requests <-chan svc.ChangeRequest,
	status chan<- svc.Status,
) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runAgentContext(ctx)
	}()

	status <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	for {
		select {
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case err := <-done:
					if err != nil {
						return true, 1
					}
				case <-time.After(20 * time.Second):
					return true, 2
				}
				return false, 0
			default:
			}
		case err := <-done:
			if err != nil {
				return true, 1
			}
			return false, 0
		}
	}
}

func runWindowsService() error {
	return svc.Run(serviceName, agentService{})
}

func installWindowsService(exePath string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()

	if existing, err := manager.OpenService(serviceName); err == nil {
		defer existing.Close()
		config, cfgErr := existing.Config()
		if cfgErr != nil {
			return cfgErr
		}
		config.BinaryPathName = fmt.Sprintf("\\\"%s\\\" run-service", exePath)
		config.StartType = mgr.StartAutomatic
		config.DisplayName = "BPC Agent"
		config.Description = "BPC secure network agent"
		if err := existing.UpdateConfig(config); err != nil {
			return err
		}
		return configureServiceRecovery()
	}

	service, err := manager.CreateService(
		serviceName,
		exePath,
		mgr.Config{
			DisplayName:  "BPC Agent",
			Description:  "BPC secure network agent",
			StartType:    mgr.StartAutomatic,
			ErrorControl: mgr.ErrorNormal,
		},
		"run-service",
	)
	if err != nil {
		return err
	}
	defer service.Close()
	return configureServiceRecovery()
}

func startWindowsService() error {
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
	status, err := service.Query()
	if err == nil && status.State == svc.Running {
		return nil
	}
	if err := service.Start(); err != nil {
		return err
	}
	return waitServiceState(service, svc.Running, 20*time.Second)
}

func stopWindowsService() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()

	service, err := manager.OpenService(serviceName)
	if err != nil {
		return nil
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped {
		return nil
	}
	if _, err := service.Control(svc.Stop); err != nil {
		return err
	}
	return waitServiceState(service, svc.Stopped, 20*time.Second)
}

func removeWindowsService() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()

	service, err := manager.OpenService(serviceName)
	if err != nil {
		return nil
	}
	defer service.Close()
	_, _ = service.Control(svc.Stop)
	_ = waitServiceState(service, svc.Stopped, 15*time.Second)
	return service.Delete()
}

func windowsServiceStatus() string {
	manager, err := mgr.Connect()
	if err != nil {
		return "unknown"
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return "not-installed"
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return "unknown"
	}
	switch status.State {
	case svc.Running:
		return "running"
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start-pending"
	case svc.StopPending:
		return "stop-pending"
	default:
		return fmt.Sprintf("state-%d", status.State)
	}
}

func waitServiceState(service *mgr.Service, desired svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == desired {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("timed out waiting for BPC Agent service state")
}

func configureServiceRecovery() error {
	out, err := runCommand(
		"sc.exe",
		"failure",
		serviceName,
		"reset=",
		"86400",
		"actions=",
		"restart/5000/restart/15000/restart/60000",
	)
	if err != nil {
		return fmt.Errorf("configure service recovery: %w: %s", err, out)
	}
	return nil
}
