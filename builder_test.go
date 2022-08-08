package gojwt_test

import (
	"fmt"
	"github.com/tobyguelly/gojwt"
	"testing"
	"time"
)

type UnitTests []struct {
	Input  fmt.Stringer
	Output fmt.Stringer
}

func (u UnitTests) Run(t *testing.T) {
	for i, test := range u {
		AssertEqual(t, test.Input, test.Output)
		t.Logf("Test %d/%d successful!", i, len(u))
	}
}

type Wrapper struct {
	value string
}

func Wrap(input string) Wrapper {
	return Wrapper{value: input}
}

func (w Wrapper) String() string {
	return w.value
}

func AssertEqual(t *testing.T, input fmt.Stringer, expected fmt.Stringer) {
	if input.String() != expected.String() {
		t.Error("Assertion Error: Value Difference\nValue 1:", input, "\b\nValue 2:", expected)
		t.FailNow()
	}
}

func TestBuilder_Setters(t *testing.T) {
	UnitTests{
		{
			Input:  gojwt.WithBuilder(),
			Output: gojwt.NewJWT(),
		},
		{
			Input: gojwt.WithBuilder().Issuer("Test Issuer").JWTID("123").Custom("user", "admin"),
			Output: gojwt.JWT{
				Header: gojwt.DefaultHeader,
				Payload: gojwt.Payload{
					Issuer: "Test Issuer",
					JWTID:  "123",
					Custom: gojwt.Map{
						"user": "admin",
					},
				},
			},
		},
		{
			Input: gojwt.WithBuilder().ExpiresIn(time.Second * 10),
			Output: gojwt.JWT{
				Header: gojwt.DefaultHeader,
				Payload: gojwt.Payload{
					Issuer:         "gojwt",
					ExpirationTime: gojwt.Now().Add(time.Second * 10),
				},
			},
		},
	}.Run(t)
}
