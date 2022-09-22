package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/tobyguelly/gojwt"
)

const (
	label = "123456"
	bits  = 2048
)

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	publicKey := privateKey.PublicKey
	if err != nil {
		fmt.Println(err.Error())
	}

	jwt := gojwt.JWT{
		Header: gojwt.Header{
			Algorithm: gojwt.AlgRS256,
			Type:      gojwt.TypJWT,
		},
		Payload: gojwt.Payload{
			Issuer:  "gojwt",
			Subject: "Example Token",
		},
	}

	jwt.Payload.Custom = gojwt.Map{
		"string": "Example String",
		"number": 1234,
	}

	err = jwt.SignWithKey(label, publicKey)
	if err != nil {
		fmt.Println("Token successfully signed!")
	}

	token, err := jwt.Parse()
	if err == nil {
		fmt.Println(token)
	}

	err = jwt.ValidateWithKey(label, *privateKey)
	if err == gojwt.ErrInvSecKey {
		fmt.Println("Invalid secret!")
	} else if err == gojwt.ErrTokNotSig {
		fmt.Println("Token has not been signed!")
	} else if err == nil {
		fmt.Println("Signature does match!")
	}
}
