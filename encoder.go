package EcdsaEncoder

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
)

func EncodePrivKey(privateKey *ecdsa.PrivateKey) (string, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey); if err != nil {
		return "", err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	return string(pemEncoded), nil
}

func EncodePubKey(publicKey *ecdsa.PublicKey) (string, error) {
	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey); if err != nil {
		return "", err
	}
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return string(pemEncodedPub), nil
}

func DecodePrivKey(privateKey string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKey));
	x509Encoded := block.Bytes
	pk, err := x509.ParseECPrivateKey(x509Encoded); if err != nil {
		return nil, err
	}

	return pk, nil
}

func DecodePubKey(publicKey string) (*ecdsa.PublicKey, error) {
	blockPub, _ := pem.Decode([]byte(publicKey))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub); if err != nil {
		return nil, err
	}
	pk := genericPublicKey.(*ecdsa.PublicKey)

	return pk, nil
}

func EcdsaEncode(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string, error) {
	pemEncoded, err := EncodePrivKey(privateKey); if err != nil {
		return "", "", err
	}
	pemEncodedPub, err := EncodePubKey(publicKey); if err != nil {
		return "", "", err
	}

	return pemEncoded, pemEncodedPub, nil
}

func EcdsaDecode(pemEncoded string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := DecodePrivKey(pemEncoded); if err != nil {
		return nil, nil, err
	}
	publicKey, err := DecodePubKey(pemEncodedPub); if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

