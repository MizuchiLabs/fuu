package devkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// signSalt is the domain separator for the signing primary, kept apart from deviceSalt because CreatePrimary is a pure function of owner seed plus inSensitive plus inPublic, so two keys on one TPM must never share a salt, and the vN must be bumped whenever the template or this call changes.
const signSalt = "github.com/mizuchilabs/fuu/v1/sign"

// signingPrimary is a loaded deterministic signing primary, a handle inside the TPM plus its parsed public key.
type signingPrimary struct {
	hnd  tpm2.TPMHandle
	name tpm2.TPM2BName
	pub  *ecdsa.PublicKey
}

// ecdsaSignature mirrors crypto/ecdsa's signature type for DER encoding.
type ecdsaSignature struct {
	R, S *big.Int
}

// SigningKey is this machine's deterministic TPM-resident ECDSA P-256 signing key.
type SigningKey struct {
	tpm transport.TPMCloser
	key *signingPrimary
	mu  sync.Mutex
}

// OpenSigning derives the signing key with nothing persisted, and a missing or unusable TPM is a hard error rather than a fallback.
func OpenSigning() (*SigningKey, error) {
	dev, err := openTPMDevice()
	if err != nil {
		return nil, fmt.Errorf("devkey: open tpm: %w", err)
	}
	key, err := createSigningPrimary(dev)
	if err != nil {
		return nil, errors.Join(err, dev.Close())
	}
	return &SigningKey{tpm: dev, key: key}, nil
}

// Public returns the public half of the signing key.
func (k *SigningKey) Public() *ecdsa.PublicKey {
	return k.key.pub
}

// Sign signs a SHA-256 digest and returns the DER encoded ECDSA signature.
func (k *SigningKey) Sign(digest []byte) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("devkey: digest is %d bytes, want the %d byte SHA-256 digest", len(digest), sha256.Size)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return signECDSA(k.tpm, k.key, digest)
}

// Close flushes the key handle and closes the TPM transport.
func (k *SigningKey) Close() error {
	_, err := tpm2.FlushContext{FlushHandle: k.key.hnd}.Execute(k.tpm)
	return errors.Join(err, k.tpm.Close())
}

// eccSignTemplate is the fixed signing template mixed into the derivation, with no auth value and no PCR policy so control of the TPM device file is the access control.
func eccSignTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256},
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

// createSigningPrimary derives the signing key from the owner seed, signSalt and eccSignTemplate, persisting nothing because reopening reproduces the key pair until the owner seed changes.
func createSigningPrimary(r transport.TPM) (*signingPrimary, error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: []byte(signSalt)}),
			},
		},
		InPublic: tpm2.New2B(eccSignTemplate()),
	}.Execute(r)
	if err != nil {
		return nil, fmt.Errorf("devkey: create signing primary: %w", err)
	}

	pub, err := publicToECDSA(rsp.OutPublic)
	if err != nil {
		_, _ = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(r)
		return nil, err
	}
	return &signingPrimary{hnd: rsp.ObjectHandle, name: rsp.Name, pub: pub}, nil
}

// signECDSA signs a SHA-256 digest with the loaded key and returns the DER encoded signature.
func signECDSA(r transport.TPM, key *signingPrimary, digest []byte) ([]byte, error) {
	rsp, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: key.hnd,
			Name:   key.name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digest: tpm2.TPM2BDigest{Buffer: digest},
		// InScheme stays NULL because the key template pins the ECDSA scheme, and the validation ticket must be explicit because a zero ticket carries Tag 0 which the TPM rejects as an invalid structure tag.
		Validation: tpm2.TPMTTKHashCheck{
			Tag:       tpm2.TPMSTHashCheck,
			Hierarchy: tpm2.TPMRHNull,
		},
	}.Execute(r)
	if err != nil {
		return nil, fmt.Errorf("devkey: sign: %w", err)
	}

	ecc, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("devkey: decode signature: %w", err)
	}
	return asn1MarshalECDSA(ecc.SignatureR.Buffer, ecc.SignatureS.Buffer)
}

// asn1MarshalECDSA encodes the raw signature halves as DER.
func asn1MarshalECDSA(r, s []byte) ([]byte, error) {
	return asn1.Marshal(ecdsaSignature{
		R: new(big.Int).SetBytes(r),
		S: new(big.Int).SetBytes(s),
	})
}

// publicToECDSA converts a TPM2BPublic into an [ecdsa.PublicKey], the ECDSA counterpart of publicToECDH so callers never parse the wire form themselves.
func publicToECDSA(pub tpm2.TPM2BPublic) (*ecdsa.PublicKey, error) {
	tp, err := pub.Contents()
	if err != nil {
		return nil, fmt.Errorf("devkey: decode public key: %w", err)
	}
	if tp.Type != tpm2.TPMAlgECC {
		return nil, errors.New("devkey: TPM key is not ECC")
	}
	point, err := tp.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("devkey: decode ECC point: %w", err)
	}
	// The TPM strips leading zero bytes while SEC 1 wants each coordinate at curve width.
	if len(point.X.Buffer) > 32 || len(point.Y.Buffer) > 32 {
		return nil, errors.New("devkey: ECC coordinate longer than 32 bytes")
	}
	// SEC 1 uncompressed form is 0x04 || X || Y with each coordinate padded to 32 bytes.
	data := make([]byte, 65)
	data[0] = 0x04
	copy(data[33-len(point.X.Buffer):33], point.X.Buffer)
	copy(data[65-len(point.Y.Buffer):65], point.Y.Buffer)

	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), data)
	if err != nil {
		return nil, fmt.Errorf("devkey: parse ECC public key: %w", err)
	}
	return key, nil
}
