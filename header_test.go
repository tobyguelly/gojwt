package gojwt_test

import (
	"github.com/tobyguelly/gojwt"
	"testing"
)

func TestHeader_IsEmpty(t *testing.T) {
	tests := []struct {
		Input          gojwt.Header
		ExpectedOutput bool
	}{
		{
			Input:          gojwt.DefaultHeader,
			ExpectedOutput: false,
		},
		{
			Input:          gojwt.Header{},
			ExpectedOutput: true,
		},
		{
			Input: gojwt.Header{
				Type: "JWT",
			},
			ExpectedOutput: false,
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

func TestHeader_Json(t *testing.T) {
	tests := []struct {
		Input          gojwt.Header
		ExpectedOutput string
	}{
		{
			Input: gojwt.Header{
				Algorithm: gojwt.AlgHS256,
				Type:      gojwt.TypJWT,
			},
			ExpectedOutput: "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
		},
		{
			Input:          gojwt.Header{},
			ExpectedOutput: "{\"alg\":\"\",\"typ\":\"\"}",
		},
		{
			Input: gojwt.Header{
				Algorithm:   gojwt.AlgHS256,
				ContentType: "JWT",
				Type:        gojwt.TypJWT,
			},
			ExpectedOutput: "{\"alg\":\"HS256\",\"cty\":\"JWT\",\"typ\":\"JWT\"}",
		},
	}
	for i, test := range tests {
		res, err := test.Input.Json()
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
