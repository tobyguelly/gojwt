package main

import (
	"errors"
	"fmt"
	"github.com/tobyguelly/gojwt"
	"time"
)

const (
	secret = "123456"
)

func main() {
	jwt := gojwt.NewJWT()

	jwt.Payload.NotBefore = gojwt.Now().Add(time.Second * 5)
	jwt.Payload.ExpirationTime = gojwt.Now().Add(time.Second * 10)

	err := jwt.Sign(secret)
	if err == nil {
		fmt.Println("Token successfully signed!")
	}

	err = jwt.Validate(secret)
	if errors.Is(err, gojwt.ErrInvTokPrd) {
		fmt.Println("Token is not valid yet!")
	}

	time.Sleep(time.Second * 7)

	err = jwt.Validate(secret)
	if err == nil {
		fmt.Println("Token is valid now!")
	}

	time.Sleep(time.Second * 7)

	err = jwt.Validate(secret)
	if errors.Is(err, gojwt.ErrInvTokPrd) {
		fmt.Println("Token has expired now!")
	}
}
