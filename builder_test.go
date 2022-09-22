package gojwt_test

import (
	"github.com/tobyguelly/gojwt"
	"testing"
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
				IssuedAt(gojwt.Unix(1)).
				NotBefore(gojwt.Unix(2)).
				ExpirationTime(gojwt.Unix(3)).
				Custom("hello", "world").
				JWTID("testId"),
			Secret:         "1234",
			ExpectedOutput: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0SXNzdWVyIiwic3ViIjoidGVzdFN1YmplY3QiLCJhdWQiOiJ0ZXN0QXVkaWVuY2UiLCJleHAiOjMsIm5iZiI6MiwiaWF0IjoxLCJqdGkiOiJ0ZXN0SWQiLCJoZWxsbyI6IndvcmxkIn0._bEv_XNOP4zcqeKZZpWkbrkzcJDgER4m7PQ0Ivq-uEM",
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
