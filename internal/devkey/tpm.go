package devkey

import (
	"crypto/ecdh"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// deviceSalt is the domain separator for the primary derivation. CreatePrimary is a pure function of owner seed plus
// inSensitive plus inPublic, so any two apps that pick the same salt and template silently share one private key.
// The module path keeps it globally unique, and the vN must be bumped whenever the template or this call changes.
const deviceSalt = "github.com/mizuchilabs/fuu/v1/device"

// primaryKey is a loaded deterministic primary, a handle inside the TPM plus its parsed public key.
type primaryKey struct {
	hnd  tpm2.TPMHandle
	name tpm2.TPM2BName
	pub  *ecdh.PublicKey
}

// Available reports whether a TPM 2.0 device can be opened on this machine, carrying the reason when it cannot.
func Available() error {
	dev, err := openTPMDevice()
	if err != nil {
		return fmt.Errorf("devkey: open tpm: %w", err)
	}
	return dev.Close()
}

// eccECDHTemplate is the fixed template mixed into the derivation, with no auth value and no PCR policy so control of the TPM device file is the access control.
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

// createPrimary derives the primary key from the owner seed, the fixed salt and the template, persisting nothing because reopening reproduces the key pair until the owner seed changes.
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

// ecdhZGen runs TPM2_ECDHZGen and returns the X coordinate in the same fixed width form crypto/ecdh uses, so a TPM key and a software key are interchangeable to callers.
func ecdhZGen(r transport.TPM, key *primaryKey, peer *ecdh.PublicKey) ([]byte, error) {
	// FillBytes panics on a coordinate wider than 32 bytes, so only a P-256 peer may reach it.
	if peer == nil || peer.Curve() != ecdh.P256() {
		return nil, errors.New("devkey: peer key is not P-256")
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
		return nil, fmt.Errorf("devkey: ecdh x coordinate is %d bytes, want 1 to 32", len(out.X.Buffer))
	}
	// The TPM may strip leading zero bytes while crypto/ecdh always returns the full width.
	shared := make([]byte, 32)
	copy(shared[32-len(out.X.Buffer):], out.X.Buffer)
	return shared, nil
}

// publicToECDH converts a TPM2BPublic into a [ecdh.PublicKey] via tpm2.ECDHPub so callers never parse the wire form themselves.
func publicToECDH(pub tpm2.TPM2BPublic) (*ecdh.PublicKey, error) {
	tp, err := pub.Contents()
	if err != nil {
		return nil, fmt.Errorf("devkey: decode public key: %w", err)
	}
	if tp.Type != tpm2.TPMAlgECC {
		return nil, errors.New("devkey: TPM key is not ECC")
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
