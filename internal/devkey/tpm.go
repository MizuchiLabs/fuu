package devkey

import (
	"crypto/ecdh"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// deviceSalt is the domain separator for the derivation. CreatePrimary is a
// pure function of owner seed, salt and template, so two apps picking the
// same salt silently share one private key. The module path keeps it unique,
// and vN bumps when the template changes.
const deviceSalt = "github.com/mizuchilabs/fuu/v1/device"

// primaryKey is a loaded deterministic primary.
type primaryKey struct {
	hnd  tpm2.TPMHandle
	name tpm2.TPM2BName
	pub  *ecdh.PublicKey
}

// errNoTPM is the honest signal that this machine has no usable TPM 2.0.
var errNoTPM = errors.New("no TPM 2.0 found on this machine, fuu has no software fallback")

// noTPMError wraps the cause with the headline and the firmware hint. Two %w
// keep every cause findable with [errors.Is], and present shows the whole
// block because a multi wrap error no longer unwraps to one cause.
func noTPMError(cause error) error {
	return fmt.Errorf(
		"%w\n%w\n\nif this machine does have a TPM, look for it in the firmware settings",
		errNoTPM, cause,
	)
}

// Available reports whether a TPM 2.0 device can be opened on this machine.
func Available() error {
	dev, err := openTPMDevice()
	if err != nil {
		return fmt.Errorf("devkey: open tpm: %w", err)
	}
	return dev.Close()
}

// eccECDHTemplate has no auth value and no PCR policy, control of the
// TPM device file is the access control.
func eccECDHTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDH,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDH,
						&tpm2.TPMSKeySchemeECDH{HashAlg: tpm2.TPMAlgSHA256},
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: []byte{}},
				Y: tpm2.TPM2BECCParameter{Buffer: []byte{}},
			},
		),
	}
}

// createPrimary persists nothing, reopening reproduces the key pair until
// the owner seed changes.
func createPrimary(r transport.TPM) (*primaryKey, error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: []byte(deviceSalt)}),
			},
		},
		InPublic: tpm2.New2B(eccECDHTemplate()),
	}.Execute(r)
	if err != nil {
		return nil, fmt.Errorf("devkey: create primary: %w", err)
	}

	pub, err := publicToECDH(rsp.OutPublic)
	if err != nil {
		_, _ = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(r)
		return nil, err
	}
	return &primaryKey{hnd: rsp.ObjectHandle, name: rsp.Name, pub: pub}, nil
}

// ecdhZGen returns the X coordinate in the fixed width form crypto/ecdh uses,
// so TPM and software keys are interchangeable.
func ecdhZGen(r transport.TPM, key *primaryKey, peer *ecdh.PublicKey) ([]byte, error) {
	// FillBytes panics on a coordinate wider than 32 bytes, so only a P-256 peer may reach it.
	if peer == nil || peer.Curve() != ecdh.P256() {
		return nil, errors.New("peer key is not P-256")
	}
	x, y, err := tpm2.ECCPoint(peer)
	if err != nil {
		return nil, fmt.Errorf("devkey: peer point: %w", err)
	}
	rsp, err := tpm2.ECDHZGen{
		KeyHandle: tpm2.AuthHandle{
			Handle: key.hnd,
			Name:   key.name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPoint: tpm2.New2B(tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: x.FillBytes(make([]byte, 32))},
			Y: tpm2.TPM2BECCParameter{Buffer: y.FillBytes(make([]byte, 32))},
		}),
	}.Execute(r)
	if err != nil {
		return nil, fmt.Errorf("devkey: ecdh: %w", err)
	}
	out, err := rsp.OutPoint.Contents()
	if err != nil {
		return nil, fmt.Errorf("devkey: decode ecdh point: %w", err)
	}
	if len(out.X.Buffer) == 0 || len(out.X.Buffer) > 32 {
		return nil, fmt.Errorf("ecdh x coordinate is %d bytes, want 1 to 32", len(out.X.Buffer))
	}
	// The TPM may strip leading zero bytes while crypto/ecdh always returns the full width.
	shared := make([]byte, 32)
	copy(shared[32-len(out.X.Buffer):], out.X.Buffer)
	return shared, nil
}

// publicToECDH turns a TPM2BPublic into a [ecdh.PublicKey] so callers never parse the wire form.
func publicToECDH(pub tpm2.TPM2BPublic) (*ecdh.PublicKey, error) {
	tp, err := pub.Contents()
	if err != nil {
		return nil, fmt.Errorf("devkey: decode public key: %w", err)
	}
	if tp.Type != tpm2.TPMAlgECC {
		return nil, errors.New("TPM key is not ECC")
	}
	params, err := tp.Parameters.ECCDetail()
	if err != nil {
		return nil, fmt.Errorf("devkey: decode ECC parameters: %w", err)
	}
	point, err := tp.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("devkey: decode ECC point: %w", err)
	}
	key, err := tpm2.ECDHPub(params, point)
	if err != nil {
		return nil, fmt.Errorf("devkey: convert ECC public key: %w", err)
	}
	return key, nil
}
