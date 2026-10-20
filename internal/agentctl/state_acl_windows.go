//go:build windows

package agentctl

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
)

func preserveStateACL(previous, next string) error {
	if _, err := os.Stat(previous); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(previous, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if acl == nil {
		return errors.New("state security descriptor has no access control list")
	}
	return windows.SetNamedSecurityInfo(next, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
