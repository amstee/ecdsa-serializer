package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"reflect"
	"github.com/amstee/ecdsa-serializer"
)

func main() {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey := &privateKey.PublicKey

	encPriv, encPub, _ := EcdsaEncoder.EcdsaEncode(privateKey, publicKey)

	fmt.Println(encPriv)
	fmt.Println(encPub)

	priv2, pub2, _ := EcdsaEncoder.EcdsaDecode(encPriv, encPub)

	if !reflect.DeepEqual(privateKey, priv2) {
		fmt.Println("Private keys do not match.")
	}
	if !reflect.DeepEqual(publicKey, pub2) {
		fmt.Println("Public keys do not match.")
	}
}
