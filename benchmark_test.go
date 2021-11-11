package gojwt

import (
	"testing"
)

func BenchmarkJWT_Sign(b *testing.B) {
	jwt := JWT{
		Header: DefaultHeader,
		Payload: Payload{
			Issuer: "gojwt",
		},
	}
	for i := 0; i < b.N; i++ {
		err := jwt.Sign("1234")
		if err != nil {
			b.Errorf("Failed benchmark while signing: %s", err.Error())
		}
	}
}

func BenchmarkJWT_Validate(b *testing.B) {
	jwt := JWT{
		Header: DefaultHeader,
		Payload: Payload{
			Issuer: "gojwt",
		},
	}
	err := jwt.Sign("1234")
	if err != nil {
		b.Errorf("Failed benchmark while signing: %s", err.Error())
	}
	for i := 0; i < b.N; i++ {
		err := jwt.Validate("1234")
		if err != nil {
			b.Errorf("Failed benchmark while validating: %s", err.Error())
		}
	}
}
