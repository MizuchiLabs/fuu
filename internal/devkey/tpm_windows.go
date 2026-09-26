//go:build windows

package devkey

import (
	"errors"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
	"github.com/google/go-tpm/tpmutil/tbs"
)

func openTPMDevice() (transport.TPMCloser, error) {
	dev, err := windowstpm.Open()
	if err == nil {
		return dev, nil
	}
	// Open hands back a transport even when the TBS context failed.
	if dev != nil {
		_ = dev.Close()
	}
	return nil, openTPMError(err)
}

// openTPMError gives a refusal that means "no chip" the shared no-TPM block.
func openTPMError(err error) error {
	if errors.Is(err, tbs.ErrTPMNotFound) {
		return noTPMError(err)
	}
	return err
}
