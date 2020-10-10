package main

import (
	"fmt"

	"github.com/studyzy/crypto/ecdsa"
	"github.com/studyzy/crypto/elliptic"
	"github.com/studyzy/crypto/x509"
)

func main() {
	k, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		fmt.Print(err)
	}
	fmt.Printf("%#v\n", k)
	pubKey := k.PublicKey
	fmt.Printf("%T %v\n", pubKey, pubKey)
	a, err := x509.MarshalPKIXPublicKey(&pubKey)
	if err != nil {
		fmt.Print(err)
	}
	fmt.Printf("%v", a)
}
