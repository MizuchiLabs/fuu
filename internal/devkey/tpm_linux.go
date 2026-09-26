//go:build linux

package devkey

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

var tpmDevices = []string{"/dev/tpmrm0", "/dev/tpm0"}

// The device nodes are root:tss 0660 by default, so a plain user needs the
// tss group before any command that touches the TPM can work.
var errTPMAccess = errors.New("this user cannot open the TPM device, only root and the tss group can")

// Both nodes missing is the honest signal that this machine has no chip at all.
var errNoTPM = errors.New("no TPM 2.0 found on this machine, fuu has no software fallback")

func openTPMDevice() (transport.TPMCloser, error) {
	var errs []error
	missing := 0
	for _, path := range tpmDevices {
		dev, err := linuxtpm.Open(path)
		if err == nil {
			return dev, nil
		}
		if errors.Is(err, fs.ErrNotExist) {
			missing++
		}
		errs = append(errs, err)
	}
	// The %w pairs keep every cause findable with errors.Is, and present shows
	// each whole block because a multi wrap error no longer unwraps to one cause.
	joined := errors.Join(errs...)
	switch {
	case slices.ContainsFunc(errs, func(err error) bool { return errors.Is(err, fs.ErrPermission) }):
		return nil, fmt.Errorf(
			"%w\n%w\n\nadd yourself to the tss group and log in again:\n    sudo usermod -aG tss $USER",
			errTPMAccess, joined,
		)
	case missing == len(errs):
		return nil, fmt.Errorf(
			"%w\n%w\n\nif this machine does have a TPM, look for it in the firmware settings",
			errNoTPM, joined,
		)
	}
	return nil, joined
}
