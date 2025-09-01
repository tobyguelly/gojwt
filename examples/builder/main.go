package main

import (
	"fmt"
	"time"

	"github.com/tobyguelly/gojwt"
)

const (
	secret = "123456"
)

func main() {
	token, err := gojwt.WithBuilder().
		Custom("username", "admin").
		ExpiresIn(time.Second * 10).
		Sign(secret)
	if err == nil {
		fmt.Println(token)
	}
}
