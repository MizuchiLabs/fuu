//go:build windows

package devkey

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpmutil/tbs"
)

// A missing chip gets the no-TPM block with the TBS cause still attached.
func TestOpenTPMErrorNotFound(t *testing.T) {
	err := openTPMError(fmt.Errorf("open tpm: %w", tbs.ErrTPMNotFound))
	if !errors.Is(err, errNoTPM) || !errors.Is(err, tbs.ErrTPMNotFound) {
		t.Fatalf("openTPMError = %v, want errNoTPM and the TBS cause", err)
	}
	if !strings.Contains(err.Error(), "firmware settings") {
		t.Fatalf("openTPMError = %v, want the firmware hint in it", err)
	}
}

// Any other refusal passes through untouched.
func TestOpenTPMErrorOther(t *testing.T) {
	other := fmt.Errorf("open tpm: %w", tbs.ErrServiceNotRunning)
	if err := openTPMError(other); !errors.Is(err, tbs.ErrServiceNotRunning) || errors.Is(err, errNoTPM) {
		t.Fatalf("openTPMError = %v, want the raw TBS error", err)
	}
}
