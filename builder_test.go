package gojwt_test

import (
	"github.com/tobyguelly/gojwt"
	"testing"
	"time"
)

func TestBuilder(t *testing.T) {
	tests := []struct {
		Input          *gojwt.Builder
		Secret         string
		ExpectedOutput string
	}{
		{
			Input: gojwt.WithBuilder().
				Issuer("testIssuer").
				Subject("testSubject").
				Audience("testAudience").
				IssuedAt(time.Unix(0, 0)).
				NotBefore(time.Unix(1, 0)).
				ExpirationTime(time.Unix(2, 0)).
				Custom("hello", "world").
				JWTID("testId"),
			Secret:         "1234",
			ExpectedOutput: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0SXNzdWVyIiwic3ViIjoidGVzdFN1YmplY3QiLCJhdWQiOiJ0ZXN0QXVkaWVuY2UiLCJleHAiOjIsIm5iZiI6MSwiaWF0IjowLCJqdGkiOiJ0ZXN0SWQiLCJoZWxsbyI6IndvcmxkIn0.z0b6-9OgddsRwxwAR8dB3Y4Ud-rG1-sbpN_3xUmy-uI",
		},
	}
	for i, test := range tests {
		token, err := test.Input.Sign(test.Secret)
		if token == test.ExpectedOutput {
			t.Logf("Passed %d/%d tests!", i+1, len(tests))
		} else {
			t.Errorf("Output and expected output did not match: %s\nFound:\t\t%s\nExpected:\t%s",
				err, token, test.ExpectedOutput,
			)
		}
	}
}
