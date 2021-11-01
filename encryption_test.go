package gojwt

import (
	"testing"
)

func TestEncodeBase64(t *testing.T) {
	tests := []struct {
		Input          string
		ExpectedOutput string
	}{
		{
			Input:          "Hello World",
			ExpectedOutput: "SGVsbG8gV29ybGQ",
		},
		{
			Input:          "8414f49e5dd98afc7af5c6994fb7ee8fe45f03aeb1c9a247c678a1a1acf67a34",
			ExpectedOutput: "ODQxNGY0OWU1ZGQ5OGFmYzdhZjVjNjk5NGZiN2VlOGZlNDVmMDNhZWIxYzlhMjQ3YzY3OGExYTFhY2Y2N2EzNA",
		},
	}
	for i, test := range tests {
		res := EncodeBase64(test.Input)
		if res == test.ExpectedOutput {
			t.Logf("Passed %d/%d tests!", i+1, len(tests))
		} else {
			t.Errorf("Output and expected output did not match: %s\nFound:\t\t%s\nExpected:\t%s",
				test.Input, res, test.ExpectedOutput,
			)
		}
	}
}

func TestDecodeBase64(t *testing.T) {
	tests := []struct {
		Input          string
		ExpectedOutput string
	}{
		{
			Input:          "SGVsbG8gV29ybGQ",
			ExpectedOutput: "Hello World",
		},
		{
			Input:          "ODQxNGY0OWU1ZGQ5OGFmYzdhZjVjNjk5NGZiN2VlOGZlNDVmMDNhZWIxYzlhMjQ3YzY3OGExYTFhY2Y2N2EzNA",
			ExpectedOutput: "8414f49e5dd98afc7af5c6994fb7ee8fe45f03aeb1c9a247c678a1a1acf67a34",
		},
	}
	for i, test := range tests {
		res, err := DecodeBase64(test.Input)
		if err != nil {
			t.Errorf("Failed test because of error: %s", err.Error())
			t.FailNow()
		}
		if string(res) == test.ExpectedOutput {
			t.Logf("Passed %d/%d tests!", i+1, len(tests))
		} else {
			t.Errorf("Output and expected output did not match: %s\nFound:\t\t%s\nExpected:\t%s",
				test.Input, string(res), test.ExpectedOutput,
			)
		}
	}
}

func TestSignHS256(t *testing.T) {
	tests := []struct {
		Input          string
		Secret         string
		ExpectError    bool
		ExpectedOutput string
	}{
		{
			Input:          "Hello World",
			Secret:         "1234",
			ExpectedOutput: "QFCJWSyjiFF759iNdFzr2v8Zmrcr9m0EA087t5KBOFs",
		},
		{
			Input:          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ",
			Secret:         "a03nbg9ab390a",
			ExpectedOutput: "HmaheHfw3srd2m0J9-tMkqErdHrunHvCPAeR8WScPos",
		},
	}
	for i, test := range tests {
		res, err := SignHS256(test.Input, test.Secret)
		if err != nil {
			t.Errorf("Failed test because of error: %s", err.Error())
			t.FailNow()
		} else {
			if res == test.ExpectedOutput {
				t.Logf("Passed %d/%d tests!", i+1, len(tests))
			} else {
				t.Errorf("Output and expected output did not match: %s, secret %s\nFound:\t\t%s\nExpected:\t%s",
					test.Input, test.Secret, res, test.ExpectedOutput,
				)
			}
		}
	}
}
