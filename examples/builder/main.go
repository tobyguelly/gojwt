package main

import (
	"fmt"
	"github.com/tobyguelly/gojwt"
	"time"
)

const (
	secret = "123456"
)

func main() {
	token, err := gojwt.WithBuilder().Custom("username", "admin").ExpiresIn(time.Second * 10).Sign(secret)
	if err == nil {
		fmt.Println(token)
	}
}
