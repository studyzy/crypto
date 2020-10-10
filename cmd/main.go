package main

import (
	"fmt"

	"github.com/studyzy/crypto/ecdsa"
	"github.com/studyzy/crypto/elliptic"
)

func main()  {
	k,err:= ecdsa.GenerateKey(elliptic.P256(),nil)
	if err!=nil{
		fmt.Print(err)
	}
	fmt.Printf("%#v",k)
}
