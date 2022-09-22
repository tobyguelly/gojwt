package gojwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/tobyguelly/gojwt"
	"testing"
)

func TestNewJWT(t *testing.T) {
	tests := []struct {
		Input          string
		ExpectedError  error
		ExpectedOutput gojwt.JWT
	}{
		{
			Input:         "asdf.jklö",
			ExpectedError: gojwt.ErrBadJWTTok,
		},
		{
			Input:         "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiIxMjA4MjAyODUyIiwic3ViIjoiMTkyNzAyNzYwMiIsIkhlbGxvIjoiV29ybGQifQ.2LHb2xST_hzGPjLQ2Yz0l9urhJU5b1CADycKklsCW5E",
			ExpectedError: nil,
			ExpectedOutput: gojwt.JWT{
				Header: gojwt.DefaultHeader,
				Payload: gojwt.Payload{
					Issuer:  "1208202852",
					Subject: "1927027602",
					Custom: map[string]interface{}{
						"Hello": "World",
					},
				},
				Signature: "2LHb2xST_hzGPjLQ2Yz0l9urhJU5b1CADycKklsCW5E",
			},
		},
	}
	for i, test := range tests {
		res, err := gojwt.LoadJWT(test.Input)
		if err != nil {
			if test.ExpectedError != nil {
				if test.ExpectedError == err {
					t.Logf("Passed %d/%d tests!", i+1, len(tests))
				} else {
					t.Errorf("Failed test because of error: %s", err.Error())
					t.FailNow()
				}
			}
		} else {
			if res.Header == test.ExpectedOutput.Header && res.Signature == test.ExpectedOutput.Signature {
				if res.Payload.Issuer == test.ExpectedOutput.Payload.Issuer &&
					res.Payload.Subject == test.ExpectedOutput.Payload.Subject &&
					res.Payload.Audience == test.ExpectedOutput.Payload.Audience &&
					res.Payload.ExpirationTime == test.ExpectedOutput.Payload.ExpirationTime &&
					res.Payload.NotBefore == test.ExpectedOutput.Payload.NotBefore &&
					res.Payload.IssuedAt == test.ExpectedOutput.Payload.IssuedAt &&
					res.Payload.JWTID == test.ExpectedOutput.Payload.JWTID {
					for key, value := range test.ExpectedOutput.Payload.Custom {
						if res.Payload.Custom[key] != value {
							t.Errorf("Output and expected output did not match: %s\nFound:\t\t%s\nExpected:\t%s",
								test.Input, res, test.ExpectedOutput,
							)
							t.FailNow()
						}
					}
					t.Logf("Passed %d/%d tests!", i+1, len(tests))
				} else {
					t.Errorf("Output and expected output did not match: %s\nFound:\t\t%s\nExpected:\t%s",
						test.Input, res, test.ExpectedOutput,
					)
				}
			} else {
				t.Errorf("Output and expected output did not match: %s\nFound:\t\t%s\nExpected:\t%s",
					test.Input, res, test.ExpectedOutput,
				)
			}
		}
	}
}

func TestJWT_IsEmpty(t *testing.T) {
	tests := []struct {
		Input          gojwt.JWT
		ExpectedOutput bool
	}{
		{
			Input: gojwt.JWT{
				Header: gojwt.DefaultHeader,
				Payload: gojwt.Payload{
					Issuer:  "1208202852",
					Subject: "1927027602",
					Custom: map[string]interface{}{
						"Hello": "World",
					},
				},
			},
			ExpectedOutput: false,
		},
		{
			Input: gojwt.JWT{
				Payload: gojwt.Payload{
					Custom: map[string]interface{}{
						"Hello": "World",
					},
				},
			},
			ExpectedOutput: false,
		},
		{
			Input: gojwt.JWT{
				Header: gojwt.DefaultHeader,
			},
			ExpectedOutput: false,
		},
		{
			Input: gojwt.JWT{
				Signature: "asdf",
			},
			ExpectedOutput: true,
		},
		{
			Input:          gojwt.JWT{},
			ExpectedOutput: true,
		},
	}
	for i, test := range tests {
		res := test.Input.IsEmpty()
		if res == test.ExpectedOutput {
			t.Logf("Passed %d/%d tests!", i+1, len(tests))
		} else {
			t.Errorf("Output and expected output did not match: %s\nFound:\t\t%t\nExpected:\t%t",
				test.Input, res, test.ExpectedOutput,
			)
		}
	}
}

func TestJWT_Validate(t *testing.T) {
	tests := []struct {
		Input         gojwt.JWT
		Secret        string
		ExpectedError error
	}{
		{
			Input: gojwt.JWT{
				Header: gojwt.Header{
					Algorithm: gojwt.AlgHS256,
					Type:      gojwt.TypJWT,
				},
				Payload: gojwt.Payload{
					Issuer:  "1208202852",
					Subject: "1927027602",
				},
				Signature: "oMtOeySl9N0eUyC4W6dKbPtYXWF9jOFR7aimds75hpE",
			},
			Secret:        "123456",
			ExpectedError: nil,
		},
		{
			Input: gojwt.JWT{
				Header: gojwt.Header{
					Algorithm: "ASDF",
					Type:      gojwt.TypJWT,
				},
				Payload: gojwt.Payload{
					Issuer:  "1208202852",
					Subject: "1927027602",
				},
				Signature: "oMtOeySl9N0eUyC4W6dKbPtYXWF9jOFR7aimds75hpE",
			},
			Secret:        "123456",
			ExpectedError: gojwt.ErrAlgNotImp,
		},
		{
			Input: gojwt.JWT{
				Header: gojwt.Header{
					Algorithm: gojwt.AlgHS256,
					Type:      gojwt.TypJWT,
				},
				Payload: gojwt.Payload{
					Issuer:  "1208202852",
					Subject: "1927027602",
				},
				Signature: "oMtOeySl9N0eUyC4W6dKbPtYXWF9jOFR7aimds75hpE",
			},
			Secret:        "1234567890",
			ExpectedError: gojwt.ErrInvSecKey,
		},
		{
			Input: gojwt.JWT{
				Header: gojwt.Header{
					Algorithm: gojwt.AlgHS256,
					Type:      gojwt.TypJWT,
				},
				Payload: gojwt.Payload{
					Issuer:  "1208202852",
					Subject: "1927027602",
				},
			},
			Secret:        "1234567890",
			ExpectedError: gojwt.ErrTokNotSig,
		},
	}
	for i, test := range tests {
		err := test.Input.Validate(test.Secret)
		if err != nil {
			if test.ExpectedError == err {
				t.Logf("Passed %d/%d tests!", i+1, len(tests))
			} else {
				t.Errorf("Output and expected output did not match: %s\nFound:\t\t%s\nExpected:\t%s",
					test.Input, err.Error(), test.ExpectedError,
				)
			}
		} else {
			t.Logf("Passed %d/%d tests!", i+1, len(tests))
		}
	}
}

func TestJWT_Sign(t *testing.T) {
	tests := []struct {
		Input         gojwt.JWT
		Secret        string
		ExpectedError error
	}{
		{
			Input: gojwt.JWT{
				Header: gojwt.Header{
					Algorithm: gojwt.AlgHS256,
					Type:      gojwt.TypJWT,
				},
				Payload: gojwt.Payload{
					Issuer: "foo",
				},
			},
			Secret:        "12345",
			ExpectedError: nil,
		},
		{
			Input: gojwt.JWT{
				Header: gojwt.Header{
					Algorithm: "ASDF",
					Type:      gojwt.TypJWT,
				},
				Payload: gojwt.Payload{
					Issuer: "foo",
				},
			},
			Secret:        "12345",
			ExpectedError: gojwt.ErrAlgNotImp,
		},
	}
	for i, test := range tests {
		err := test.Input.Sign(test.Secret)
		if err != nil {
			if test.ExpectedError == err {
				t.Logf("Passed %d/%d tests!", i+1, len(tests))
			} else {
				t.Errorf("Output and expected output did not match: %s\nFound:\t\t%s\nExpected:\t%s",
					test.Input, err.Error(), test.ExpectedError,
				)
			}
		} else {
			t.Logf("Passed %d/%d tests!", i+1, len(tests))
		}
	}
}

func TestJWT_SignAndValidateWithKey(t *testing.T) {
	type rsaTest struct {
		Input         gojwt.JWT
		Label         string
		PublicKey     rsa.PublicKey
		PrivateKey    rsa.PrivateKey
		SignToken     bool
		ExpectError   bool
		ExpectedError error
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("Failed test because of error: %s", err.Error())
		t.FailNow()
	}
	var tests []rsaTest
	for i := 0; i < 5; i++ {
		test := rsaTest{
			Input: gojwt.JWT{
				Header: gojwt.Header{
					Algorithm: gojwt.AlgRS256,
					Type:      gojwt.TypJWT,
				},
				Payload: gojwt.Payload{
					Issuer: fmt.Sprintf(""),
				},
				Signature: "",
			},
			Label:         "",
			PublicKey:     privateKey.PublicKey,
			PrivateKey:    *privateKey,
			SignToken:     true,
			ExpectError:   false,
			ExpectedError: nil,
		}
		tests = append(tests, test)
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("Failed test because of error: %s", err.Error())
		t.FailNow()
	}
	tests = append(tests, rsaTest{
		Input: gojwt.JWT{
			Header: gojwt.Header{
				Algorithm: gojwt.AlgRS256,
				Type:      gojwt.TypJWT,
			},
			Payload: gojwt.Payload{
				Issuer: fmt.Sprintf(""),
			},
			Signature: "",
		},
		Label:         "",
		PublicKey:     wrongKey.PublicKey,
		PrivateKey:    *privateKey,
		SignToken:     true,
		ExpectError:   true,
		ExpectedError: gojwt.ErrInvSecKey,
	})
	tests = append(tests, rsaTest{
		Input: gojwt.JWT{
			Header: gojwt.Header{
				Algorithm: "Hello World",
				Type:      gojwt.TypJWT,
			},
		},
		Label:         "",
		PublicKey:     privateKey.PublicKey,
		PrivateKey:    *privateKey,
		SignToken:     true,
		ExpectError:   true,
		ExpectedError: gojwt.ErrAlgNotImp,
	})
	tests = append(tests, rsaTest{
		Input: gojwt.JWT{
			Header: gojwt.Header{
				Algorithm: gojwt.AlgRS256,
				Type:      gojwt.TypJWT,
			},
		},
		Label:         "",
		PublicKey:     privateKey.PublicKey,
		PrivateKey:    *privateKey,
		SignToken:     false,
		ExpectError:   true,
		ExpectedError: gojwt.ErrTokNotSig,
	})
	for i, test := range tests {
		if test.SignToken {
			err := test.Input.SignWithKey(test.Label, test.PublicKey)
			if err != nil {
				if test.ExpectError && err == test.ExpectedError {
					t.Logf("Passed %d/%d tests!", i+1, len(tests))
				} else {
					t.Errorf("Failed test because of error: %s", err.Error())
					t.FailNow()
				}
			}
		}
		err := test.Input.ValidateWithKey(test.Label, test.PrivateKey)
		if test.ExpectError {
			if err != nil {
				if err == test.ExpectedError {
					t.Logf("Passed %d/%d tests!", i+1, len(tests))
				} else {
					t.Errorf("Failed test because of error: %s", err.Error())
					t.FailNow()
				}
			} else {
				t.Errorf("Failed test because an error was expected, but non happened.")
				t.FailNow()
			}
		} else {
			if err == nil {
				t.Logf("Passed %d/%d tests!", i+1, len(tests))
			} else {
				t.Errorf("Failed test because an error was expected, but non happened.")
				t.FailNow()
			}
		}
	}
}

func TestJWT_String(t *testing.T) {
	tests := []struct {
		Input          gojwt.JWT
		ExpectedOutput string
	}{
		{
			Input: gojwt.JWT{
				Header: gojwt.DefaultHeader,
				Payload: gojwt.Payload{
					Issuer:  "1208202852",
					Subject: "1927027602",
					Custom: map[string]interface{}{
						"Hello": "World",
					},
				},
				Signature: "2LHb2xST_hzGPjLQ2Yz0l9urhJU5b1CADycKklsCW5E",
			},
			ExpectedOutput: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiIxMjA4MjAyODUyIiwic3ViIjoiMTkyNzAyNzYwMiIsIkhlbGxvIjoiV29ybGQifQ.2LHb2xST_hzGPjLQ2Yz0l9urhJU5b1CADycKklsCW5E",
		},
		{
			Input: gojwt.JWT{
				Header: gojwt.DefaultHeader,
				Payload: gojwt.Payload{
					Issuer:  "1208202852",
					Subject: "1927027602",
					Custom: map[string]interface{}{
						"Hello": "World",
					},
				},
			},
			ExpectedOutput: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiIxMjA4MjAyODUyIiwic3ViIjoiMTkyNzAyNzYwMiIsIkhlbGxvIjoiV29ybGQifQ.LYjdH12gE9YUKzqhDALzV6yae7FGqN3ODRzSn4ZVttQ",
		},
		{
			Input: gojwt.JWT{
				Header: gojwt.Header{
					Algorithm: "12345",
					Type:      gojwt.TypJWT,
				},
				Payload: gojwt.Payload{
					Issuer:  "1208202852",
					Subject: "1927027602",
				},
			},
			ExpectedOutput: "eyJhbGciOiIxMjM0NSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiIxMjA4MjAyODUyIiwic3ViIjoiMTkyNzAyNzYwMiJ9.u7jPI4TU0k8RAnqVj3Hf5qkvSKFCHVmUD-Foghi75ko",
		},
	}
	for i, test := range tests {
		res, err := test.Input.Parse()
		if err != nil || res == test.ExpectedOutput {
			t.Logf("Passed %d/%d tests!", i+1, len(tests))
		} else {
			t.Errorf("Output and expected output did not match: %s\nFound:\t\t%s\nExpected:\t%s",
				test.Input, res, test.ExpectedOutput,
			)
		}
	}
}

func TestJWT_Data(t *testing.T) {
	tests := []struct {
		Input          gojwt.JWT
		ExpectedOutput string
	}{
		{
			Input: gojwt.JWT{
				Header: gojwt.DefaultHeader,
				Payload: gojwt.Payload{
					Issuer:  "1208202852",
					Subject: "1927027602",
					Custom: map[string]interface{}{
						"Hello": "World",
					},
				},
			},
			ExpectedOutput: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiIxMjA4MjAyODUyIiwic3ViIjoiMTkyNzAyNzYwMiIsIkhlbGxvIjoiV29ybGQifQ",
		},
	}
	for i, test := range tests {
		res, err := test.Input.Data()
		if err != nil {
			t.Errorf("Failed test because of error: %s", err.Error())
			t.FailNow()
		}
		if res == test.ExpectedOutput {
			t.Logf("Passed %d/%d tests!", i+1, len(tests))
		} else {
			t.Errorf("Output and expected output did not match: %s\nFound:\t\t%s\nExpected:\t%s",
				test.Input, res, test.ExpectedOutput,
			)
		}
	}
}
