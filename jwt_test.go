package gojwt

import (
	"testing"
)

func TestNewJWT(t *testing.T) {
	tests := []struct {
		Input          string
		ExpectedError  error
		ExpectedOutput JWT
	}{
		{
			Input:         "asdf.jklö",
			ExpectedError: ErrBadJWTTok,
		},
		{
			Input:         "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiIxMjA4MjAyODUyIiwic3ViIjoiMTkyNzAyNzYwMiIsIkhlbGxvIjoiV29ybGQifQ.2LHb2xST_hzGPjLQ2Yz0l9urhJU5b1CADycKklsCW5E",
			ExpectedError: nil,
			ExpectedOutput: JWT{
				Header: DefaultHeader,
				Payload: Payload{
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
		res, err := NewJWT(test.Input)
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
		Input          JWT
		ExpectedOutput bool
	}{
		{
			Input: JWT{
				Header: DefaultHeader,
				Payload: Payload{
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
			Input: JWT{
				Payload: Payload{
					Custom: map[string]interface{}{
						"Hello": "World",
					},
				},
			},
			ExpectedOutput: false,
		},
		{
			Input: JWT{
				Header: DefaultHeader,
			},
			ExpectedOutput: false,
		},
		{
			Input: JWT{
				Signature: "asdf",
			},
			ExpectedOutput: true,
		},
		{
			Input:          JWT{},
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

func TestJWT_DecodeSignature(t *testing.T) {
	tests := []struct {
		Input          JWT
		ExpectedOutput string
	}{
		{
			Input: JWT{
				Signature: "ODQxNGY0OWU1ZGQ5OGFmYzdhZjVjNjk5NGZiN2VlOGZlNDVmMDNhZWIxYzlhMjQ3YzY3OGExYTFhY2Y2N2EzNA",
			},
			ExpectedOutput: "8414f49e5dd98afc7af5c6994fb7ee8fe45f03aeb1c9a247c678a1a1acf67a34",
		},
	}
	for i, test := range tests {
		err := test.Input.DecodeSignature()
		if err != nil {
			t.Errorf("Failed test because of error: %s", err.Error())
			t.FailNow()
		}
		if test.Input.Signature == test.ExpectedOutput {
			t.Logf("Passed %d/%d tests!", i+1, len(tests))
		} else {
			t.Errorf("Output and expected output did not match: %s\nFound:\t\t%s\nExpected:\t%s",
				test.Input, test.Input.Signature, test.ExpectedOutput,
			)
		}
	}
}

func TestJWT_EncodeSignature(t *testing.T) {
	tests := []struct {
		Input          JWT
		ExpectedOutput string
	}{
		{
			Input: JWT{
				Signature: "8414f49e5dd98afc7af5c6994fb7ee8fe45f03aeb1c9a247c678a1a1acf67a34",
			},
			ExpectedOutput: "ODQxNGY0OWU1ZGQ5OGFmYzdhZjVjNjk5NGZiN2VlOGZlNDVmMDNhZWIxYzlhMjQ3YzY3OGExYTFhY2Y2N2EzNA",
		},
	}
	for i, test := range tests {
		test.Input.EncodeSignature()
		if test.Input.Signature == test.ExpectedOutput {
			t.Logf("Passed %d/%d tests!", i+1, len(tests))
		} else {
			t.Errorf("Output and expected output did not match: %s\nFound:\t\t%s\nExpected:\t%s",
				test.Input, test.Input.Signature, test.ExpectedOutput,
			)
		}
	}
}

func TestJWT_Validate(t *testing.T) {
	tests := []struct {
		Input         JWT
		Secret        string
		ExpectedError error
	}{
		{
			Input: JWT{
				Header: Header{
					Algorithm: AlgHS256,
					Type:      TypJWT,
				},
				Payload: Payload{
					Issuer:  "1208202852",
					Subject: "1927027602",
				},
				Signature: "oMtOeySl9N0eUyC4W6dKbPtYXWF9jOFR7aimds75hpE",
			},
			Secret:        "123456",
			ExpectedError: nil,
		},
		{
			Input: JWT{
				Header: Header{
					Algorithm: "ASDF",
					Type:      TypJWT,
				},
				Payload: Payload{
					Issuer:  "1208202852",
					Subject: "1927027602",
				},
				Signature: "oMtOeySl9N0eUyC4W6dKbPtYXWF9jOFR7aimds75hpE",
			},
			Secret:        "123456",
			ExpectedError: ErrAlgNotImp,
		},
		{
			Input: JWT{
				Header: Header{
					Algorithm: AlgHS256,
					Type:      TypJWT,
				},
				Payload: Payload{
					Issuer:  "1208202852",
					Subject: "1927027602",
				},
				Signature: "oMtOeySl9N0eUyC4W6dKbPtYXWF9jOFR7aimds75hpE",
			},
			Secret:        "1234567890",
			ExpectedError: ErrInvSecKey,
		},
		{
			Input: JWT{
				Header: Header{
					Algorithm: AlgHS256,
					Type:      TypJWT,
				},
				Payload: Payload{
					Issuer:  "1208202852",
					Subject: "1927027602",
				},
			},
			Secret:        "1234567890",
			ExpectedError: ErrTokNotSig,
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
		Input         JWT
		Secret        string
		ExpectedError error
	}{
		{
			Input: JWT{
				Header: Header{
					Algorithm: AlgHS256,
					Type:      TypJWT,
				},
				Payload: Payload{
					Issuer: "foo",
				},
			},
			Secret:        "12345",
			ExpectedError: nil,
		},
		{
			Input: JWT{
				Header: Header{
					Algorithm: "ASDF",
					Type:      TypJWT,
				},
				Payload: Payload{
					Issuer: "foo",
				},
			},
			Secret:        "12345",
			ExpectedError: ErrAlgNotImp,
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

func TestJWT_String(t *testing.T) {
	tests := []struct {
		Input          JWT
		ExpectedOutput string
	}{
		{
			Input: JWT{
				Header: DefaultHeader,
				Payload: Payload{
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
			Input: JWT{
				Header: DefaultHeader,
				Payload: Payload{
					Issuer:  "1208202852",
					Subject: "1927027602",
					Custom: map[string]interface{}{
						"Hello": "World",
					},
				},
			},
			ExpectedOutput: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiIxMjA4MjAyODUyIiwic3ViIjoiMTkyNzAyNzYwMiIsIkhlbGxvIjoiV29ybGQifQ.LYjdH12gE9YUKzqhDALzV6yae7FGqN3ODRzSn4ZVttQ",
		},
	}
	for i, test := range tests {
		res := test.Input.String()
		if res == test.ExpectedOutput {
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
		Input          JWT
		ExpectedOutput string
	}{
		{
			Input: JWT{
				Header: DefaultHeader,
				Payload: Payload{
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
