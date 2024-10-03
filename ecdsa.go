package k6ecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log"
	"math/big"

	"go.k6.io/k6/js/modules"
)

func init() {
	modules.Register("k6/x/file", new(ECDSA))
}

type ECDSASignature struct {
	R, S *big.Int
}

type ECDSA struct{}

func (c *ECDSA) SignECDSAWithPEM(privateKeyPEM string, payload []byte) (string, error) {
	// log.Panic("TESTTT")

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", errors.New("failed to decode PEM block containing private key")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	priv, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", errors.New("expected ECDSA private key")
	}

	hashed := sha256.Sum256(payload)

	r, s, err := ecdsa.Sign(rand.Reader, priv, hashed[:])
	if err != nil {
		return "", err
	}

	sig := &ECDSASignature{R: r, S: s}

	der, err := asn1.Marshal(*sig)
	if err != nil {
		return "", err
	}

	base64Signature := base64.StdEncoding.EncodeToString(der)
	// log.Printf("Signed payload: %s\n", base64Signature)
	return base64Signature, nil
}

func (c *ECDSA) verifyECDSASignatureWithPEM(publicKeyPEM string, payload string, base64Signature string) (bool, error) {
	log.Println("Verifying signature....")

	// Decode the public key
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return false, errors.New("failed to decode PEM block containing public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return false, errors.New("expected ECDSA public key")
	}

	// Decode the base64 signature
	der, err := base64.StdEncoding.DecodeString(base64Signature)
	if err != nil {
		return false, err
	}

	// Unmarshal the R and S components of the ASN.1-encoded signature
	sig := &ECDSASignature{}
	_, err = asn1.Unmarshal(der, sig)
	if err != nil {
		return false, err
	}

	// Compute the SHA256 hash of the payload
	hashed := sha256.Sum256([]byte(payload))

	// Validate the signature
	valid := ecdsa.Verify(ecdsaPubKey, hashed[:], sig.R, sig.S)
	log.Printf("Signature Verification Status: %v", valid)
	return valid, nil
}
