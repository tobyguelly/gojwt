package gojwt_test

import (
	"github.com/tobyguelly/gojwt"
	"testing"
	"time"
)

func TestTime_Marshal(t *testing.T) {
	tests := []struct {
		Input          gojwt.Time
		ExpectedOutput string
	}{
		{
			Input:          *gojwt.Unix(0),
			ExpectedOutput: "0",
		},
		{
			Input:          *gojwt.Unix(0).Add(time.Second * 1000),
			ExpectedOutput: "1000",
		},
	}
	for i, test := range tests {
		if res, err := test.Input.MarshalJSON(); err == nil && string(res) == test.ExpectedOutput {
			t.Logf("Passed %d/%d tests!", i+1, len(tests))
		} else {
			t.Errorf("Output and expected output did not match: %s\nFound:\t\t%s\nExpected:\t%s",
				err, res, test.ExpectedOutput,
			)
		}
	}
}

func TestTime_Unmarshal(t *testing.T) {
	tests := []struct {
		Input          string
		ExpectedOutput *gojwt.Time
	}{
		{
			Input:          "0",
			ExpectedOutput: gojwt.Unix(0),
		},
		{
			Input:          "1000",
			ExpectedOutput: gojwt.Unix(1000),
		},
	}
	for i, test := range tests {
		unmarshalled := gojwt.Now()
		if err := unmarshalled.UnmarshalJSON([]byte(test.Input)); err == nil && unmarshalled.Time.Unix() == test.ExpectedOutput.Unix() {
			t.Logf("Passed %d/%d tests!", i+1, len(tests))
		} else {
			t.Errorf("Output and expected output did not match: %s\nFound:\t\t%d\nExpected:\t%d",
				err, unmarshalled.Unix(), test.ExpectedOutput.Unix(),
			)
		}
	}
}
