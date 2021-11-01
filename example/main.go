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
			Issuer:  "1208202852",
			Subject: "1927027602",
		},
	}

	jwt.Payload.Custom = map[string]interface{}{
		"Hello": "World",
	}

	err := jwt.Sign(secret)
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Println(jwt.String())

	err = jwt.Validate(secret)
	if err == gojwt.ErrInvSecKey {
		fmt.Println("Invalid secret!")
	} else if err == gojwt.ErrTokNotSig {
		fmt.Println("Token has not been signed!")
	} else if err == nil {
		fmt.Println("Signature does match!")
	}
}
