package gojwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/tobyguelly/gojwt"
	"testing"
)

const (
	bits   = 2048
	secret = "1234"
	label  = ""
)

func BenchmarkJWT_Sign(b *testing.B) {
	jwt := gojwt.JWT{
		Header: gojwt.DefaultHeader,
		Payload: gojwt.Payload{
			Issuer: "gojwt",
		},
	}
	for i := 0; i < b.N; i++ {
		err := jwt.Sign(secret)
		if err != nil {
			b.Errorf("Failed benchmark while signing: %s", err.Error())
		}
	}
}

func BenchmarkJWT_SignWithKey(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		b.Errorf("Failed benchmark while generating key: %s", err.Error())
		b.FailNow()
	}
	jwt := gojwt.JWT{
		Header: gojwt.Header{
			Algorithm: gojwt.AlgRS256,
			Type:      gojwt.TypJWT,
		},
		Payload: gojwt.Payload{
			Issuer: "gojwt",
		},
	}
	for i := 0; i < b.N; i++ {
		err = jwt.SignWithKey(label, privateKey.PublicKey)
		if err != nil {
			b.Errorf("Failed benchmark while signing: %s", err.Error())
			b.FailNow()
		}
	}
}

func BenchmarkJWT_Validate(b *testing.B) {
	jwt := gojwt.JWT{
		Header: gojwt.DefaultHeader,
		Payload: gojwt.Payload{
			Issuer: "gojwt",
		},
	}
	err := jwt.Sign(secret)
	if err != nil {
		b.Errorf("Failed benchmark while signing: %s", err.Error())
		b.FailNow()
	}
	for i := 0; i < b.N; i++ {
		err := jwt.Validate(secret)
		if err != nil {
			b.Errorf("Failed benchmark while validating: %s", err.Error())
			b.FailNow()
		}
	}
}

func BenchmarkJWT_ValidateWithKey(b *testing.B) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		b.Errorf("Failed benchmark while generating key: %s", err.Error())
		b.FailNow()
	}
	jwt := gojwt.JWT{
		Header: gojwt.Header{
			Algorithm: gojwt.AlgRS256,
			Type:      gojwt.TypJWT,
		},
		Payload: gojwt.Payload{
			Issuer: "gojwt",
		},
	}
	err = jwt.SignWithKey(label, privateKey.PublicKey)
	if err != nil {
		b.Errorf("Failed benchmark while signing: %s", err.Error())
		b.FailNow()
	}
	for i := 0; i < b.N; i++ {
		err = jwt.ValidateWithKey(label, *privateKey)
		if err != nil {
			b.Errorf("Failed benchmark while validating: %s", err.Error())
			b.FailNow()
		}
	}
}
