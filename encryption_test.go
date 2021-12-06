package gojwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/tobyguelly/gojwt"
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
		res := gojwt.EncodeBase64(test.Input)
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
		res, err := gojwt.DecodeBase64(test.Input)
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
		res, err := gojwt.SignHS256(test.Input, test.Secret)
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

func TestSignHS384(t *testing.T) {
	tests := []struct {
		Input          string
		Secret         string
		ExpectError    bool
		ExpectedOutput string
	}{
		{
			Input:          "Hello World",
			Secret:         "1234",
			ExpectedOutput: "zLeeUJE1zWX0_n5AvQNEp6EPGo8U-V8VFsANEBTm3lZFs4ZfBmsFozwt89PEEDtb",
		},
		{
			Input:          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ",
			Secret:         "a03nbg9ab390a",
			ExpectedOutput: "sHz_46K4CN5fagvoNKEDmXggriqCRAqjvyWkgES-kXKFp_06gPRf5Bi1xhZA31on",
		},
	}
	for i, test := range tests {
		res, err := gojwt.SignHS384(test.Input, test.Secret)
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

func TestSignHS512(t *testing.T) {
	tests := []struct {
		Input          string
		Secret         string
		ExpectError    bool
		ExpectedOutput string
	}{
		{
			Input:          "Hello World",
			Secret:         "1234",
			ExpectedOutput: "gVQasAcuBc8ZKjhEClQmmvkn-TnUPtIgoBdgxeqL1A_ZN4_laaE1IKWk78XKuWsloknoFem5kGtkHOSRCCg6_g",
		},
		{
			Input:          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ",
			Secret:         "a03nbg9ab390a",
			ExpectedOutput: "eOSGFETACFzW3KxPf74jdaNHdIF1DkwXQEiYEfhvLmDEMCLvwPEXyr8dZ1Jl6_Ng5PTA2cD166KifsntIh2DCg",
		},
	}
	for i, test := range tests {
		res, err := gojwt.SignHS512(test.Input, test.Secret)
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

func TestEncryptAndDecryptRS256(t *testing.T) {
	type rsaTest struct {
		Input      string
		Label      []byte
		PublicKey  rsa.PublicKey
		PrivateKey rsa.PrivateKey
	}
	var tests []rsaTest
	for i := 0; i < 4; i++ {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Errorf("Failed test because of error: %s", err.Error())
			t.FailNow()
		}
		test := rsaTest{
			Input:      "Hello World",
			Label:      []byte{},
			PublicKey:  privateKey.PublicKey,
			PrivateKey: *privateKey,
		}
		tests = append(tests, test)
	}
	for i, test := range tests {
		signature, err := gojwt.EncryptRS256(test.Input, test.Label, test.PublicKey)
		if err != nil {
			t.Errorf("Failed test because of error: %s", err.Error())
			t.FailNow()
		} else {
			result, err := gojwt.DecryptRS256(signature, test.Label, test.PrivateKey)
			if err != nil {
				t.Errorf("Failed test because of error: %s", err.Error())
				t.FailNow()
			} else {
				if test.Input == result {
					t.Logf("Passed %d/%d tests!", i+1, len(tests))
				} else {
					t.Errorf("Output and expected output did not match: %s, secret %s\nFound:\t\t%s\nExpected:\t%s",
						test.Input, test.Label, result, test.Input,
					)
				}
			}
		}
	}
}

func TestEncryptAndDecryptRS384(t *testing.T) {
	type rsaTest struct {
		Input      string
		Label      []byte
		PublicKey  rsa.PublicKey
		PrivateKey rsa.PrivateKey
	}
	var tests []rsaTest
	for i := 0; i < 4; i++ {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Errorf("Failed test because of error: %s", err.Error())
			t.FailNow()
		}
		test := rsaTest{
			Input:      "Hello World",
			Label:      []byte{},
			PublicKey:  privateKey.PublicKey,
			PrivateKey: *privateKey,
		}
		tests = append(tests, test)
	}
	for i, test := range tests {
		signature, err := gojwt.EncryptRS384(test.Input, test.Label, test.PublicKey)
		if err != nil {
			t.Errorf("Failed test because of error: %s", err.Error())
			t.FailNow()
		} else {
			result, err := gojwt.DecryptRS384(signature, test.Label, test.PrivateKey)
			if err != nil {
				t.Errorf("Failed test because of error: %s", err.Error())
				t.FailNow()
			} else {
				if test.Input == result {
					t.Logf("Passed %d/%d tests!", i+1, len(tests))
				} else {
					t.Errorf("Output and expected output did not match: %s, secret %s\nFound:\t\t%s\nExpected:\t%s",
						test.Input, test.Label, result, test.Input,
					)
				}
			}
		}
	}
}

func TestEncryptAndDecryptRS512(t *testing.T) {
	type rsaTest struct {
		Input      string
		Label      []byte
		PublicKey  rsa.PublicKey
		PrivateKey rsa.PrivateKey
	}
	var tests []rsaTest
	for i := 0; i < 4; i++ {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Errorf("Failed test because of error: %s", err.Error())
			t.FailNow()
		}
		test := rsaTest{
			Input:      "Hello World",
			Label:      []byte{},
			PublicKey:  privateKey.PublicKey,
			PrivateKey: *privateKey,
		}
		tests = append(tests, test)
	}
	for i, test := range tests {
		signature, err := gojwt.EncryptRS512(test.Input, test.Label, test.PublicKey)
		if err != nil {
			t.Errorf("Failed test because of error: %s", err.Error())
			t.FailNow()
		} else {
			result, err := gojwt.DecryptRS512(signature, test.Label, test.PrivateKey)
			if err != nil {
				t.Errorf("Failed test because of error: %s", err.Error())
				t.FailNow()
			} else {
				if test.Input == result {
					t.Logf("Passed %d/%d tests!", i+1, len(tests))
				} else {
					t.Errorf("Output and expected output did not match: %s, secret %s\nFound:\t\t%s\nExpected:\t%s",
						test.Input, test.Label, result, test.Input,
					)
				}
			}
		}
	}
}
