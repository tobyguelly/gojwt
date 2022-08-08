package main

import (
	"fmt"
	"github.com/tobyguelly/gojwt"
)

const (
	secret = "123456"
)

func main() {
	jwt := gojwt.JWT{
		Header: gojwt.DefaultHeader,
		Payload: gojwt.Payload{
			Issuer:  "gojwt",
			Subject: "Example Token",
		},
	}

	jwt.Payload.Custom = gojwt.Map{
		"string": "Example String",
		"number": 1234,
	}

	err := jwt.Sign(secret)
	if err == nil {
		fmt.Println("Token successfully signed!")
	}

	token, err := jwt.Parse()
	if err == nil {
		fmt.Println(token)
	}

	err = jwt.Validate(secret)
	if err == gojwt.ErrInvSecKey {
		fmt.Println("Invalid secret!")
	} else if err == gojwt.ErrTokNotSig {
		fmt.Println("Token has not been signed!")
	} else if err == nil {
		fmt.Println("Signature does match!")
	}
}
