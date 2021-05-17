package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
)

func GenerateKeypair() (prvKeyPemEncodded []byte, pubKeyPemEncodded []byte, err error) {
	prvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ecdsa.GenerateKey: %w", err)
	}

	prvKeyPemEncodded, err = x509.MarshalECPrivateKey(prvKey)
	if err != nil {
		return nil, nil, fmt.Errorf("x509.MarshalECPrivateKey: %w", err)
	}

	pubKeyPemEncodded, err = x509.MarshalPKIXPublicKey(&prvKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("x509.MarshalPKIXPublicKey: %w", err)
	}

	return prvKeyPemEncodded, pubKeyPemEncodded, nil
}
