package vapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"fmt"
)

/*
+--------------+----------------+-----------------------------------------------+-------------------------------------------+-----------------------------------------------+--------------------------------------------+
| Go enum      | OAuth2 / JOSE  | SAML XMLDSig                                  | Other protocols                           | Estimated security                            | Notes                                      |
+--------------+----------------+-----------------------------------------------+-------------------------------------------+-----------------------------------------------+--------------------------------------------+
| HS256        | HS256          | HMAC-SHA256 (rare, non-standard in SAML)      | HTTP Message Signatures, JWS              | ~128-bit (requires secret key)                | Symmetric MAC, not public-key signature.    |
| HS384        | HS384          | HMAC-SHA384 (rare)                            | HTTP Message Signatures                   | ~192-bit                                      | Rarely used outside JWT.                    |
| HS512        | HS512          | HMAC-SHA512 (rare)                            | HTTP Message Signatures                   | ~256-bit                                      | Strongest HMAC variant.                     |
|              |                |                                               |                                           |                                               |                                            |
| RS256        | RS256          | rsa-sha256                                    | CMS/PKCS#7, X.509                         | ~112-bit (RSA-2048)                           | OAuth2/OIDC default.                        |
| RS384        | RS384          | rsa-sha384                                    | CMS/PKCS#7                                | ~112-bit (RSA-2048)                           | SHA-384 adds no RSA strength.               |
| RS512        | RS512          | rsa-sha512                                    | CMS/PKCS#7                                | ~112-bit (RSA-2048)                           | Often paired with RSA-4096.                 |
|              |                |                                               |                                           |                                               |                                            |
| PS256        | PS256          | sha256-rsa-MGF1 (RSA-PSS)                     | TLS 1.3, CMS                              | ~112-bit (RSA-2048)                           | Recommended RSA variant today.              |
| PS384        | PS384          | sha384-rsa-MGF1                               | TLS 1.3                                   | ~112-bit (RSA-2048)                           | Stronger hash only.                         |
| PS512        | PS512          | sha512-rsa-MGF1                               | TLS 1.3                                   | ~112-bit (RSA-2048)                           | Usually with RSA-4096.                      |
|              |                |                                               |                                           |                                               |                                            |
| ES256        | ES256          | ecdsa-sha256                                  | WebAuthn, FIDO2, COSE (ES256)             | ~128-bit                                      | Most common ECC signature today.            |
| ES384        | ES384          | ecdsa-sha384                                  | COSE (ES384)                              | ~192-bit                                      | Enterprise / long-term security.            |
| ES512        | ES512          | ecdsa-sha512                                  | COSE (ES512)                              | ~256-bit (P-521)                              | Uses P-521 despite "512".                   |
|              |                |                                               |                                           |                                               |                                            |
| Ed25519      | EdDSA          | ed25519 (XMLDSig 2.0 / modern libs)           | WebAuthn, SSH, TLS, OpenPGP               | ~128-bit                                      | Fast, deterministic, recommended.           |
| Ed448        | EdDSA          | ed448 (XMLDSig 2.0 / modern libs)             | OpenPGP                                   | ~224-bit                                      | Rarely deployed.                            |
|              |                |                                               |                                           |                                               |                                            |
| ES256K       | ES256K         | ecdsa-secp256k1-sha256 (non-standard)         | COSE ES256K, DID, Blockchain              | ~128-bit                                      | Bitcoin/Ethereum ecosystem.                 |
|              |                |                                               |                                           |                                               |                                            |
| RSASHA1      | (none)         | rsa-sha1                                      | XMLDSig 1.0                               | ~80-bit (collision attacks on SHA-1)          | Verification only. Deprecated.              |
+--------------+----------------+-----------------------------------------------+-------------------------------------------+-----------------------------------------------+--------------------------------------------+

Approximate equivalent key strengths:

    RSA-2048  ≈ 112-bit symmetric
    RSA-3072  ≈ 128-bit symmetric
    RSA-4096  ≈ 152-bit symmetric

    P-256     ≈ 128-bit symmetric
    P-384     ≈ 192-bit symmetric
    P-521     ≈ 256-bit symmetric

    Ed25519   ≈ 128-bit symmetric
    Ed448     ≈ 224-bit symmetric

Rough brute-force estimates (assuming ideal attacks):

    80-bit   : feasible for nation states over time (deprecated)
    112-bit  : >10^15 years
    128-bit  : ~10^19 years
    192-bit  : ~10^38 years
    224-bit  : ~10^48 years
    256-bit  : ~10^57 years

Notes:
  - The RSA rows assume RSA-2048 unless a larger key is used.
  - RS256/RS384/RS512 differ only in the hash function; RSA key size determines
    the actual security level.
  - Likewise for PS256/384/512.
  - ES512 actually uses curve P-521, not a 512-bit curve.
  - OAuth2/OIDC and JWT use the JOSE algorithm names shown above.
  - WebAuthn uses COSE algorithm identifiers internally (e.g. ES256, EdDSA),
    but the commonly exposed names correspond to those shown.
*/

type SigAlg int

const (
	SigAlgUnknown SigAlg = iota

	// HMAC — MACs, not public-key signatures.
	// Used by JWS/JWT, OAuth/OIDC and HTTP Message Signatures.
	SigAlgHS256
	SigAlgHS384
	SigAlgHS512

	// RSA PKCS#1 v1.5 with SHA-2.
	SigAlgRS256
	SigAlgRS384
	SigAlgRS512

	// ECDSA with SHA-2.
	SigAlgES256 // P-256 + SHA-256
	SigAlgES384 // P-384 + SHA-384
	SigAlgES512 // P-521 + SHA-512

	// RSA-PSS with SHA-2.
	SigAlgPS256
	SigAlgPS384
	SigAlgPS512

	// Edwards-curve signatures.
	SigAlgEd25519
	SigAlgEd448

	// Optional/niche: secp256k1 + SHA-256.
	SigAlgES256K

	// Legacy verification only; never use for new signatures.
	SigAlgRSASHA1
)

func NewSigAlgFromOAuth(s string) (SigAlg, error) {
	switch s {
	case "HS256":
		return SigAlgHS256, nil
	case "HS384":
		return SigAlgHS384, nil
	case "HS512":
		return SigAlgHS512, nil
	case "RS256":
		return SigAlgRS256, nil
	case "RS384":
		return SigAlgRS384, nil
	case "RS512":
		return SigAlgRS512, nil
	case "ES256":
		return SigAlgES256, nil
	case "ES384":
		return SigAlgES384, nil
	case "ES512":
		return SigAlgES512, nil
	case "PS256":
		return SigAlgPS256, nil
	case "PS384":
		return SigAlgPS384, nil
	case "PS512":
		return SigAlgPS512, nil
	case "EdDSA", "Ed25519":
		return SigAlgEd25519, nil
	case "Ed448":
		return SigAlgEd448, nil
	case "ES256K":
		return SigAlgES256K, nil
	case "RS1":
		return SigAlgRSASHA1, nil
	}
	return SigAlgUnknown, fmt.Errorf("unknown alg: %s", s)
}

func (sa SigAlg) ToOAuth() (string, error) {
	switch sa {
	case SigAlgHS256:
		return "HS256", nil
	case SigAlgHS384:
		return "HS384", nil
	case SigAlgHS512:
		return "HS512", nil
	case SigAlgRS256:
		return "RS256", nil
	case SigAlgRS384:
		return "RS384", nil
	case SigAlgRS512:
		return "RS512", nil
	case SigAlgES256:
		return "ES256", nil
	case SigAlgES384:
		return "ES384", nil
	case SigAlgES512:
		return "ES512", nil
	case SigAlgPS256:
		return "PS256", nil
	case SigAlgPS384:
		return "PS384", nil
	case SigAlgPS512:
		return "PS512", nil
	case SigAlgEd25519:
		return "EdDSA", nil
	case SigAlgEd448:
		return "Ed448", nil
	case SigAlgES256K:
		return "ES256K", nil
	case SigAlgRSASHA1:
		return "RS1", nil
	default:
		return "unknown", ErrNotApplicable
	}
}

func NewFromSAML(s string) (SigAlg, error) {
	switch s {
	case "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256":
		return SigAlgHS256, nil
	case "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384":
		return SigAlgHS384, nil
	case "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512":
		return SigAlgHS512, nil
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
		return SigAlgRS256, nil
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":
		return SigAlgRS384, nil
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":
		return SigAlgRS512, nil
	case "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256":
		return SigAlgES256, nil
	case "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384":
		return SigAlgES384, nil
	case "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512":
		return SigAlgES512, nil
	case "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1":
		return SigAlgPS256, nil
	case "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1":
		return SigAlgPS384, nil
	case "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1":
		return SigAlgPS512, nil
	case "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519":
		return SigAlgEd25519, nil
	case "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed448":
		return SigAlgEd448, nil
	case "http://www.w3.org/2001/04/xmldsig-more#ecdsa-secp256k1-sha256":
		return SigAlgES256K, nil
	case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
		return SigAlgRSASHA1, nil
	default:
		return SigAlgUnknown, fmt.Errorf("unknown alg: %s", s)
	}
}

func (sa SigAlg) ToSAML() (string, error) {
	switch sa {
	case SigAlgHS256:
		return "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", nil
	case SigAlgHS384:
		return "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384", nil
	case SigAlgHS512:
		return "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512", nil
	case SigAlgRS256:
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", nil
	case SigAlgRS384:
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", nil
	case SigAlgRS512:
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", nil
	case SigAlgES256:
		return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", nil
	case SigAlgES384:
		return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", nil
	case SigAlgES512:
		return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", nil
	case SigAlgPS256:
		return "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1", nil
	case SigAlgPS384:
		return "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1", nil
	case SigAlgPS512:
		return "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1", nil
	case SigAlgEd25519:
		return "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519", nil
	case SigAlgEd448:
		return "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed448", nil
	case SigAlgES256K:
		return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-secp256k1-sha256", nil
	case SigAlgRSASHA1:
		return "http://www.w3.org/2000/09/xmldsig#rsa-sha1", nil
	default:
		return "unknown", ErrNotApplicable
	}
}

func (s SigAlg) Hash() crypto.Hash {
	switch s {
	case SigAlgRSASHA1:
		return crypto.SHA1
	case SigAlgHS256, SigAlgRS256, SigAlgES256, SigAlgPS256, SigAlgES256K:
		return crypto.SHA256
	case SigAlgHS384, SigAlgRS384, SigAlgES384, SigAlgPS384:
		return crypto.SHA384
	case SigAlgHS512, SigAlgRS512, SigAlgES512, SigAlgPS512:
		return crypto.SHA512
	case SigAlgUnknown, SigAlgEd25519, SigAlgEd448:
		return crypto.Hash(0)
	default:
		return crypto.Hash(0)
	}
}

func (s SigAlg) HashFunc() crypto.Hash {
	return s.Hash()
}

type Message []byte

func (d Message) Kind() string {
	return "bytes"
}

type Signer struct {
	Kid string
	Alg SigAlg
	Key crypto.Signer
}

// Sign implements [SignerSchemer].
func (s *Signer) Sign(ctx context.Context, artifact Message, options ...SigAlg) ([]byte, error) {
	alg := s.Alg
	if len(options) != 0 {
		alg = options[0]
	}
	digest := []byte(artifact)
	if hash := alg.Hash(); hash != 0 {
		if !hash.Available() {
			return nil, &ErrorCategory{Category: ErrNotApplicable, Cause: fmt.Errorf("hash %v is unavailable", hash)}
		}
		h := hash.New()
		_, _ = h.Write(artifact)
		digest = h.Sum(nil)
	}
	return s.Key.Sign(rand.Reader, digest, alg)
}

type SignVerifier struct {
	Kid string
	Alg SigAlg
	Key crypto.PublicKey
}

// VerifySignature implements [SignatureVerificationSchemer].
func (s *SignVerifier) VerifySignature(signature []byte, digest []byte, options ...SigAlg) error {
	panic("unimplemented")
}

var _ SignerSchemer[Message, SigAlg] = &Signer{}
var _ SignatureVerificationSchemer[SigAlg] = &SignVerifier{}
