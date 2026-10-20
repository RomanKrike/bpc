//go:build windows

package agentctl

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

func TestStateReplacementPreservesACLAndLockedIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	old := State{DeviceID: "existing", PrivateKey: "synthetic-old-key"}
	if err := SaveState(path, old); err != nil {
		t.Fatal(err)
	}
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + tokenUser.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err := SaveState(path, old); err != nil {
		t.Fatal(err)
	}
	after, _ := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if before.String() != after.String() {
		t.Fatal("replacement changed protected state permissions")
	}
	raw, _ := os.ReadFile(path)
	utf, _ := windows.UTF16PtrFromString(path)
	handle, err := windows.CreateFile(utf, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	if err := SaveState(path, State{DeviceID: "different"}); err == nil {
		t.Fatal("locked identity unexpectedly replaced")
	}
	current, _ := os.ReadFile(path)
	if string(current) != string(raw) {
		t.Fatal("failed replacement lost original identity")
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".state-*"))
	if len(leftovers) != 0 {
		t.Fatal("credential temporary file left behind")
	}
}
