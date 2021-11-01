package gojwt

import (
	"testing"
)

func TestHeader_IsEmpty(t *testing.T) {
	tests := []struct {
		Input          Header
		ExpectedOutput bool
	}{
		{
			Input:          DefaultHeader,
			ExpectedOutput: false,
		},
		{
			Input:          Header{},
			ExpectedOutput: true,
		},
		{
			Input: Header{
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
		Input          Header
		ExpectedOutput string
	}{
		{
			Input: Header{
				Algorithm: AlgHS256,
				Type:      TypJWT,
			},
			ExpectedOutput: "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
		},
		{
			Input:          Header{},
			ExpectedOutput: "{\"alg\":\"\",\"typ\":\"\"}",
		},
		{
			Input: Header{
				Algorithm:   AlgHS256,
				ContentType: "JWT",
				Type:        TypJWT,
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
