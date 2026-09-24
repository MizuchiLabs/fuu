//go:build !linux && !windows

package devkey

import (
	"errors"

	"github.com/google/go-tpm/tpm2/transport"
)

func openTPMDevice() (transport.TPMCloser, error) {
	return nil, errors.New("TPM device keys are not supported on this platform")
}
