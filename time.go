package gojwt

import (
	"strconv"
	"time"
)

// Time is a struct wrapping a time.Time value from the standard library.
// It implements the json.Marshaler and json.Unmarshaler interface,
// and the encoding.TextMarshaler and encoding.TextUnmarshaler interface
// to override the marshalling to create UNIX timestamps like specified
// in the JWT standard.
type Time struct {
	time.Time
}

// Wrap wraps a standard library time.Time value.
func Wrap(time time.Time) *Time {
	return &Time{Time: time}
}

// Now wraps the current standard library time.Time value.
func Now() *Time {
	return Wrap(time.Now())
}

// Unix loads a timestamp from UNIX seconds.
func Unix(seconds int64) *Time {
	return Wrap(time.Unix(seconds, 0))
}

// Add adds a time.Duration to a Time.
func (this *Time) Add(duration time.Duration) *Time {
	this.Time = this.Time.Add(duration)
	return this
}

// MarshalText is the implementation of the encoding.TextMarshaler interface.
// It parses the Time value into a UNIX-Timestamp.
func (this *Time) MarshalText() ([]byte, error) {
	if this.Time.IsZero() {
		return []byte("null"), nil
	}
	return []byte(strconv.FormatInt(this.Time.Unix(), 10)), nil
}

// UnmarshalText is the implementation of the encoding.TextUnmarshaler interface.
// It parses an UNIX-Timestamp into a Time value.
func (this *Time) UnmarshalText(data []byte) error {
	res, err := strconv.ParseInt(string(data), 10, 64)
	this.Time = time.Unix(res, 0)
	return err
}

// MarshalJSON is the implementation of the json.Marshaler interface.
// It parses the Time value into a UNIX-Timestamp.
func (this *Time) MarshalJSON() ([]byte, error) {
	return this.MarshalText()
}

// UnmarshalJSON is the implementation of the json.Unmarshaler interface.
// It parses an UNIX-Timestamp into a Time value.
func (this *Time) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	return this.UnmarshalText(data)
}
