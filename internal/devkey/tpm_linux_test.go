//go:build linux

package devkey

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The default on Linux: the device nodes belong to root and the tss group, so
// the refusal has to carry the fix.
func TestOpenTPMDeviceDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens any path whatever the mode says")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	swapDevices(t, filepath.Join(dir, "tpmrm0"), filepath.Join(dir, "tpm0"))

	_, err := openTPMDevice()
	if !errors.Is(err, errTPMAccess) || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("openTPMDevice = %v, want errTPMAccess and fs.ErrPermission", err)
	}
	if !strings.Contains(err.Error(), "sudo usermod -aG tss $USER") {
		t.Fatalf("openTPMDevice = %v, want the tss fix in it", err)
	}
}

// A machine without a TPM says so instead of blaming permissions.
func TestOpenTPMDeviceMissing(t *testing.T) {
	dir := t.TempDir()
	swapDevices(t, filepath.Join(dir, "tpmrm0"), filepath.Join(dir, "tpm0"))

	_, err := openTPMDevice()
	if !errors.Is(err, errNoTPM) {
		t.Fatalf("openTPMDevice = %v, want errNoTPM", err)
	}
	if strings.Contains(err.Error(), "tss") {
		t.Fatalf("openTPMDevice = %v, want no tss hint here", err)
	}
	if !strings.Contains(err.Error(), "firmware settings") {
		t.Fatalf("openTPMDevice = %v, want the firmware hint in it", err)
	}
}

// A node that exists but misbehaves is not "no TPM", and not a permissions story either.
func TestOpenTPMDeviceMixed(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "tpm0")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	swapDevices(t, filepath.Join(dir, "tpmrm0"), file)

	_, err := openTPMDevice()
	if err == nil {
		t.Fatal("openTPMDevice succeeded, want an error")
	}
	if errors.Is(err, errNoTPM) || errors.Is(err, errTPMAccess) {
		t.Fatalf("openTPMDevice = %v, want no headline sentinel", err)
	}
}

func swapDevices(t *testing.T, paths ...string) {
	t.Helper()
	old := tpmDevices
	tpmDevices = paths
	t.Cleanup(func() { tpmDevices = old })
}
