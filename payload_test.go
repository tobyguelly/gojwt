package gojwt

import "testing"

func TestPayload_IsEmpty(t *testing.T) {
	tests := []struct {
		Input          Payload
		ExpectedOutput bool
	}{
		{
			Input: Payload{
				Issuer: "1234",
			},
			ExpectedOutput: false,
		},
		{
			Input:          Payload{},
			ExpectedOutput: true,
		},
		{
			Input: Payload{
				Custom: map[string]interface{}{
					"hello": "world",
				},
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

func TestPayload_GetSetCustom(t *testing.T) {
	tests := []struct {
		Input Payload
		Set   map[string]interface{}
	}{
		{
			Input: Payload{
				Issuer: "1234",
			},
			Set: map[string]interface{}{
				"hello": "world",
				"foo":   "bar",
			},
		},
	}
	for i, test := range tests {
		for key, value := range test.Set {
			test.Input.SetCustom(key, value)
		}
		for key, value := range test.Set {
			res := test.Input.GetCustom(key)
			if res != value {
				t.Errorf("Output and expected output did not match: %s\nFound:\t\t%s\nExpected:\t%s",
					test.Input, res, value,
				)
			}
		}
		t.Logf("Passed %d/%d tests!", i+1, len(tests))
	}
}

func TestPayload_Json(t *testing.T) {
	tests := []struct {
		Input          Payload
		ExpectedOutput string
	}{
		{
			Input: Payload{
				Issuer: "1234",
			},
			ExpectedOutput: "{\"iss\":\"1234\"}",
		},
		{
			Input:          Payload{},
			ExpectedOutput: "{}",
		},
		{
			Input: Payload{
				Custom: map[string]interface{}{
					"hello": "world",
				},
			},
			ExpectedOutput: "{\"hello\":\"world\"}",
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
