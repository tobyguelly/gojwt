package main

import (
	"errors"
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

	token, err := jwt.SignParse(secret)
	if err == nil {
		fmt.Println("Token successfully signed!")
		fmt.Println(token)
	}

	err = jwt.Validate(secret)
	if errors.Is(err, gojwt.ErrInvSecKey) {
		fmt.Println("Invalid secret!")
	} else if errors.Is(err, gojwt.ErrTokNotSig) {
		fmt.Println("Token has not been signed!")
	} else if err == nil {
		fmt.Println("Signature does match!")
	}
}
